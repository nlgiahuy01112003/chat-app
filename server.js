require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const pg = require('pg');
const socketIo = require('socket.io');
const http = require('http');
const { encryptCaesar, decryptCaesar, encrypt3DES, decrypt3DES, encryptRSA, decryptRSA } = require('./encryption');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');
app.use(express.static('public'));

const db = new pg.Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

db.connect((err) => {
    if (err) {
        console.error('Database connection error:', err.stack);
    } else {
        console.log('Connected to the database');
    }
});

app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/register', (req, res) => {
    res.render('registration');
});

app.post('/register', async (req, res) => {
    const { user_name, password, name, department } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO "user" (user_name, password) VALUES ($1, $2)', [user_name, hashedPassword]);
        await db.query('INSERT INTO user_info (user_name, name, department) VALUES ($1, $2, $3)', [user_name, name, department]);
        res.redirect('/login');
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).send('Error registering user');
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { user_name, password } = req.body;
    try {
        const result = await db.query('SELECT password FROM "user" WHERE user_name = $1', [user_name]);
        if (result.rows.length > 0 && await bcrypt.compare(password, result.rows[0].password)) {
            res.redirect('/rooms?user=' + user_name);
        } else {
            res.redirect('/login');
        }
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).send('Error logging in');
    }
});

app.get('/rooms', async (req, res) => {
    const user_name = req.query.user;
    try {
        const roomsResult = await db.query('SELECT room.id, room.room_name FROM room JOIN room_member ON room.id = room_member.room_id WHERE room_member.user_name = $1', [user_name]);
        res.render('rooms', { user_name, rooms: roomsResult.rows });
    } catch (err) {
        console.error('Error fetching rooms:', err);
        res.status(500).send('Error fetching rooms');
    }
});

app.post('/create-room', async (req, res) => {
    const { room_name, user_name } = req.body;
    try {
        const roomResult = await db.query(
            'INSERT INTO room (room_name, created_by) VALUES ($1, $2) RETURNING id',
            [room_name, user_name]
        );
        const roomId = roomResult.rows[0].id;
        await db.query('INSERT INTO room_member (room_id, user_name) VALUES ($1, $2)', [roomId, user_name]);
        res.redirect(`/rooms?user=${user_name}`);
    } catch (err) {
        console.error('Error creating room:', err);
        res.status(500).send('Error creating room');
    }
});

app.post('/invite', async (req, res) => {
    const { room_id, user_name, inviter } = req.body;
    try {
        const roomCheck = await db.query('SELECT created_by FROM room WHERE id = $1', [room_id]);
        if (roomCheck.rows.length > 0) {
            const roomCreator = roomCheck.rows[0].created_by;
            if (roomCreator === inviter) {
                await db.query('INSERT INTO room_member (room_id, user_name) VALUES ($1, $2)', [room_id, user_name]);
                res.redirect(`/rooms?user=${inviter}`);
            } else {
                res.status(403).send('You are not authorized to invite users to this room');
            }
        } else {
            res.status(400).send('Room ID does not exist');
        }
    } catch (err) {
        console.error('Error inviting user:', err);
        res.status(500).send('Error inviting user');
    }
});

app.get('/chat', async (req, res) => {
    const { user_name, room } = req.query;
    
    // Log the received query parameters
    console.log('Received query parameters:', req.query);
    
    try {
        const roomId = parseInt(room, 10);

        if (isNaN(roomId)) {
            console.error('Invalid room ID:', room);
            return res.send('Invalid room ID.');
        }

        console.log(`Fetching room data for user: ${user_name}, room: ${roomId}`);

        const roomResult = await db.query(
            'SELECT room.id, room.room_name, room.created_by FROM room LEFT JOIN room_member ON room.id = room_member.room_id WHERE room.id = $1 AND (room_member.user_name = $2 OR room.created_by = $3)',
            [roomId, user_name, user_name]
        );

        console.log(`Room query result for user: ${user_name}, room: ${roomId}`, roomResult.rows);

        if (roomResult.rows.length > 0) {
            res.render('chat', { user_name, room: roomId });
        } else {
            console.error('User not authorized or room does not exist:', user_name, roomId);
            res.send('You are not authorized to view this room.');
        }
    } catch (err) {
        console.error('Error fetching room:', err);
        res.status(500).send('Error fetching room');
    }
});

io.on('connection', (socket) => {
    socket.on('join room', (room) => {
        socket.join(room);
    });

    socket.on('chat message', async (msg) => {
        const { user_name, message_context, room } = msg;
        try {
            const encryptedMessage = encryptCaesar(encrypt3DES(encryptRSA(message_context)));
            await db.query('INSERT INTO message (user_name, message_context, room_id) VALUES ($1, $2, $3)', [user_name, encryptedMessage, room]);
            io.to(room).emit('chat message', { user_name, message_context: encryptedMessage });
        } catch (err) {
            console.error('Error sending chat message:', err);
        }
    });

    socket.on('decrypt message', async (msg) => {
        const { user_name, message_context, room } = msg;
        try {
            const decryptedMessage = decryptRSA(decrypt3DES(decryptCaesar(message_context)));
            io.to(room).emit('decrypted message', { user_name, message_context: decryptedMessage });
        } catch (err) {
            console.error('Error decrypting message:', err);
        }
    });
});

server.listen(3000, () => {
    console.log('Server is running on port 3000');
});
