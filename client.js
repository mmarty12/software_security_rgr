const net = require('net');
const crypto = require('crypto');
const readline = require('readline');

const clientMessage = crypto.randomBytes(16).toString('hex');

const preMasterSecret = crypto.randomBytes(16);
console.log('pms', preMasterSecret);
let sessionKey = null;

const client = net.createConnection(3000, 'localhost', () => {
  console.log('Connected to server.');
  console.log(`Sent HELLO message to server: ${clientMessage}`);
  client.write(JSON.stringify({ type: 'hello', message: clientMessage }));
});

client.on('data', (data) => {
  try {
    const message = JSON.parse(data.toString());

    if (message.type === 'hello') {
      console.log(`Received message from server: ${message.message}`);
      console.log(`Received public key from server:\n${message.publicKey}`);

      const encryptedPreMaster = crypto.publicEncrypt({ key: message.publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, preMasterSecret).toString('base64');
      console.log(`Sent pre-master secret: ${encryptedPreMaster}`);
      client.write(JSON.stringify({ type: 'premaster', message: encryptedPreMaster }));

      sessionKey = crypto.createHash('sha256').update(preMasterSecret).digest();
      console.log(`Session key: ${sessionKey.toString('hex')}`);
    } else if (sessionKey) {
      const iv = sessionKey.slice(0, 16);
      const decipher = crypto.createDecipheriv('aes-256-ctr', sessionKey, iv);
      const decryptedMessage = decipher.update(message.message, 'base64', 'utf8') + decipher.final('utf8');

      if (message.type === 'ready') {
        console.log('Session established successfully!');
        promptUserInput();
      } else {
        console.log(`On server side: ${decryptedMessage}`);
        promptUserInput();
      }
    }
  } catch (err) {
    console.error('Error processing server message:', err.message);
  }
});

client.on('error', (err) => {
  console.error('Client error:', err.message);
});

client.on('end', () => {
  console.log('Disconnected from server.');
});

const IOreadline = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function sendSecureMessage(messageObj) {
  const iv = sessionKey.slice(0, 16);
  const cipher = crypto.createCipheriv('aes-256-ctr', sessionKey, iv);
  const encryptedMessage = cipher.update(messageObj.message, 'utf8', 'base64') + cipher.final('base64');
  client.write(JSON.stringify({ type: 'message', message: encryptedMessage }));
}

function promptUserInput() {
  IOreadline.question('Enter your message: ', (message) => {
    const messageObj = {
      message: message,
    };
    sendSecureMessage(messageObj);
  });
}
