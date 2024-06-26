require('dotenv').config();
const crypto = require('crypto');
const NodeRSA = require('node-rsa');

const caesarShift = parseInt(process.env.CAESAR_SHIFT);

function encryptCaesar(text, shift = caesarShift) {
    return text.split('').map(char => String.fromCharCode(char.charCodeAt(0) + shift)).join('');
}

function decryptCaesar(text, shift = caesarShift) {
    return text.split('').map(char => String.fromCharCode(char.charCodeAt(0) - shift)).join('');
}

const key3DES = Buffer.from(process.env.KEY_3DES, 'utf8');
const iv3DES = Buffer.from(process.env.IV_3DES, 'utf8');

function encrypt3DES(text) {
    const cipher = crypto.createCipheriv('des-ede3-cbc', key3DES, iv3DES);
    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

function decrypt3DES(encrypted) {
    const decipher = crypto.createDecipheriv('des-ede3-cbc', key3DES, iv3DES);
    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

const key = new NodeRSA();
key.importKey(process.env.RSA_PRIVATE_KEY, 'private');
key.importKey(process.env.RSA_PUBLIC_KEY, 'public');

function encryptRSA(text) {
    return key.encrypt(text, 'base64');
}

function decryptRSA(encrypted) {
    return key.decrypt(encrypted, 'utf8');
}

module.exports = {
    encryptCaesar,
    decryptCaesar,
    encrypt3DES,
    decrypt3DES,
    encryptRSA,
    decryptRSA,
};
