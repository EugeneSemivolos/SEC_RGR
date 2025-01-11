const net = require('net');
const crypto = require('crypto');
const fs = require('fs');

const PORT = 5000;

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const serverRandom = crypto.randomBytes(16);
let sessionKey;

const server = net.createServer((client) => {
    console.log('Client connected');

    client.on('data', (data) => handleClientMessage(client, data));
    client.on('end', () => console.log('Client disconnected'));
});

server.listen(PORT, () => console.log(`Server is listening on port ${PORT}`));

function handleClientMessage(client, data) {
    const message = JSON.parse(data);

    switch (message.type) {
        case 'hello':
            respondToHello(client, message);
            break;
        case 'premasterSecret':
            processPremasterSecret(client, message);
            break;
        case 'secureMessage':
            handleSecureMessage(client, message);
            break;
        case 'secureFile':
            handleSecureFile(message);
            break;
    }
}

function respondToHello(client, message) {
    console.log(`Server: Received client hello: ${message.clientRandom}`);

    client.write(JSON.stringify({
        type: 'serverHello',
        serverRandom: serverRandom.toString('hex'),
        publicKey: publicKey.export({ type: 'pkcs1', format: 'pem' })
    }));
}

function processPremasterSecret(client, message) {
    console.log('Server: Processing encrypted premaster secret');

    const premasterSecret = crypto.privateDecrypt(
        privateKey,
        Buffer.from(
            message.encryptedPremasterSecret,
            'hex'
        )
    );
    console.log(`Server: Decrypted premaster secret: ${premasterSecret.toString('hex')}`);

    sessionKey = crypto.createHash('sha256').update(Buffer.concat([
        Buffer.from(message.clientRandom, 'hex'),
        serverRandom,
        premasterSecret
    ])).digest();

    console.log(`Server: Session key derived: ${sessionKey.toString('hex')}`);

    client.write(JSON.stringify({
        type: 'ready',
        serverRandom: serverRandom.toString('hex'),
        premasterSecret: premasterSecret.toString('hex')
    }));
}

function handleSecureMessage(client, message) {
    const decryptedMessage = decryptData(message.encryptedMessage, message.tag);
    console.log(`Server: Received secure message: ${decryptedMessage}`);

    const encryptedResponse = encryptData('Hello, secure client!');
    client.write(JSON.stringify({
        type: 'secureMessage',
        encryptedMessage: encryptedResponse.encryptedData,
        tag: encryptedResponse.authTag
    }));
}

function handleSecureFile(message) {
    const decryptedFile = decryptData(message.encryptedFile, message.tag);
    fs.writeFileSync('received_file.txt', decryptedFile);
    console.log('Server: Secure file saved as received_file.txt');
}

function encryptData(data) {
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, Buffer.alloc(16, 0));
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return {
        encryptedData: encrypted.toString('hex'),
        authTag: cipher.getAuthTag().toString('hex')
    };
}

function decryptData(encryptedData, tag) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, Buffer.alloc(16, 0));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    return Buffer.concat([
        decipher.update(Buffer.from(encryptedData, 'hex')),
        decipher.final()
    ]).toString();
}
