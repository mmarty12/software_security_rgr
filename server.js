const net = require('net');
const crypto = require('crypto');
const PORT = 3000;

const serverMessage = crypto.randomBytes(16).toString('hex');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicKeyExport = publicKey.export({ type: 'spki', format: 'pem' });

let sessionKey = null;

const server = net.createServer((socket) => {
  console.log('Client connected.');

  socket.on('data', (data) => {
    const message = JSON.parse(data.toString());

    if (message.type === 'hello') {
      console.log(`Received HELLO from client: ${message.message}`);
      const response = JSON.stringify({
        type: 'hello',
        message: serverMessage,
        publicKey: publicKeyExport,
      });
      console.log(`Sent HELLO message to client: ${serverMessage}`);
      console.log(`Sent public key to client:\n${publicKeyExport}`);
      socket.write(response);
    } else if (message.type === 'premaster') {
      console.log(`Received pre-master secret: ${message.message}`);
      const preMasterSecret = crypto.privateDecrypt({ key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(message.message, 'base64'));
      console.log(`Decrypted pre-master secret: ${preMasterSecret.toString('base64')}`);

      sessionKey = crypto.createHash('sha256').update(preMasterSecret).digest();
      console.log(`Session key: ${sessionKey.toString('hex')}`);

      const cipher = crypto.createCipheriv('aes-256-ctr', sessionKey, sessionKey.slice(0, 16));
      const encryptedReady = cipher.update('ready', 'utf8', 'base64') + cipher.final('base64');
      socket.write(JSON.stringify({ type: 'ready', message: encryptedReady }));
    } else if (message.type === 'message') {
      console.log('Session established successfully!');

      const decipher = crypto.createDecipheriv('aes-256-ctr', sessionKey, sessionKey.slice(0, 16));
      const decryptedMessage = decipher.update(message.message, 'base64', 'utf8') + decipher.final('utf8');
      console.log(`Received message from client: ${decryptedMessage}`);

      const responseMessage = `Server received: '${decryptedMessage}'`;
      const cipherResponse = crypto.createCipheriv('aes-256-ctr', sessionKey, sessionKey.slice(0, 16));
      const encryptedResponse = cipherResponse.update(responseMessage, 'utf8', 'base64') + cipherResponse.final('base64');
      socket.write(JSON.stringify({ type: 'message', message: encryptedResponse }));
    }
  });

  socket.on('end', () => {
    console.log('Client disconnected.');
  });
});

server.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});
