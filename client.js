const net = require('net');
const crypto = require('crypto');
const fs = require('fs');

const PORT = 5000;
const clientRandom = crypto.randomBytes(16);
let sessionKey;

const client = net.createConnection(PORT, () => {
    console.log('Connected to server');

    console.log('Client: Sending hello');
    client.write(JSON.stringify({
        type: 'hello',
        clientRandom: clientRandom.toString('hex')
    }));
});

client.on('data', handleServerMessage);
client.on('end', () => console.log('Disconnected from server'));

function handleServerMessage(data) {
    const message = JSON.parse(data);

    switch (message.type) {
        case 'serverHello':
            processServerHello(message);
            break;
        case 'ready':
            finalizeHandshake(message);
            break;
        case 'secureMessage':
            decryptServerMessage(message);
            break;
    }
}

function processServerHello(message) {
    console.log(`Client: Received server hello: ${message.serverRandom}`);
    const serverPublicKey = crypto.createPublicKey({ key: message.publicKey, format: 'pem', type: 'pkcs1' });
    const premasterSecret = crypto.randomBytes(16);
    console.log(`Client: Generated premaster secret: ${premasterSecret.toString('hex')}`);

    const encryptedPremasterSecret = crypto.publicEncrypt(serverPublicKey, premasterSecret);

    console.log('Client: Sending encrypted premaster secret');
    client.write(JSON.stringify({
        type: 'premasterSecret',
        encryptedPremasterSecret: encryptedPremasterSecret.toString('hex'),
        clientRandom: clientRandom.toString('hex')
    }));
}

function finalizeHandshake(message) {
    sessionKey = crypto.createHash('sha256').update(Buffer.concat([
        Buffer.from(clientRandom, 'hex'),
        Buffer.from(message.serverRandom, 'hex'),
        Buffer.from(message.premasterSecret, 'hex')
    ])).digest();

    console.log('Client: Derived session key:', sessionKey.toString('hex'));
    console.log('Client: Secure channel established!');

    sendEncryptedMessage('Hello, secure server!');
    sendEncryptedFile('example.txt');
}

function decryptServerMessage(message) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, Buffer.alloc(16, 0));
    decipher.setAuthTag(Buffer.from(message.tag, 'hex'));
    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(message.encryptedMessage, 'hex')),
        decipher.final()
    ]);
    console.log(`Client: Received message from server: ${decrypted.toString()}`);
}

function sendEncryptedMessage(content) {
    const { encryptedData, authTag } = encryptData(content);
    console.log('Client: Sending encrypted message');
    client.write(JSON.stringify({
        type: 'secureMessage',
        encryptedMessage: encryptedData,
        tag: authTag
    }));
}

function sendEncryptedFile(filePath) {
    const fileBuffer = fs.readFileSync(filePath);
    const { encryptedData, authTag } = encryptData(fileBuffer);
    console.log('Client: Sending encrypted file');
    client.write(JSON.stringify({
        type: 'secureFile',
        encryptedFile: encryptedData,
        tag: authTag
    }));
}

function encryptData(data) {
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, Buffer.alloc(16, 0));
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return {
        encryptedData: encrypted.toString('hex'),
        authTag: cipher.getAuthTag().toString('hex')
    };
}
