const NodeRSA = require('node-rsa');
const fs = require('fs');

const key = new NodeRSA({ b: 512 });

const publicKey = key.exportKey('public');
const privateKey = key.exportKey('private');

fs.writeFileSync('public_key.pem', publicKey);
fs.writeFileSync('private_key.pem', privateKey);

console.log('Keys generated and saved to files.');
