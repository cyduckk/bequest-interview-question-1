//Digital Signature Scheme with SHA-256 and RSA is implemented to ensure data
//integrity (no tampering of client or server communication)

import express from "express";
import cors from "cors";
import * as crypto from 'crypto';

const PORT = 8080;
const app = express();
const database = { data: "Hello World" };


let { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,  
  publicKeyEncoding: {
      type: 'spki',       // Standard format for public key
      format: 'pem'       // Most common format
  },
  privateKeyEncoding: {
      type: 'pkcs8',      // Standard format for private key
      format: 'pem'       // Most common format
  }
});


app.use(cors());
app.use(express.json());

// Routes
app.get("/", (req, res) => {
  // The message you want to sign
  const message = database.data;

  // Create a signer and pass in the message
  const signer = crypto.createSign('sha256');
  signer.update(message);
  const signature = signer.sign(privateKey, 'base64'); // signature in base64

  // Send the message, signature, and public key
  res.json({ message, signature, publicKey });
});


app.post("/", async (req, res) => {
  const { message, signature, public_key } = req.body.sent_data;

  // Convert the Base64 encoded public key and signature to a buffer
  const publicKeyBuf = Buffer.from(public_key, 'base64');
  const signatureBuf = Buffer.from(signature, 'base64');

  // Import the public key
  const importedPublicKey = crypto.createPublicKey({
    key: publicKeyBuf,
    format:'der',
    type: 'spki',
  });

  // Hash the received message using SHA-256
  const hash = crypto.createHash('sha256');
  hash.update(message);
  const messageDigest = hash.digest();

  // Verify the signature; decrypt to the hash of the message
  // Server is supposed to verify the signature against the original message
  const isVerified = crypto.verify(
    "sha256",  
    Buffer.from(message),  
    {
      key: importedPublicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    signatureBuf 
  );

  //if verified set database
  if (isVerified) {
    console.log("Signature verified, updating database.");
    database.data = message;
    res.sendStatus(200);
  //if not verified log to console, and send to client
  } else {
    console.log("Signature verification failed.");
    res.status(401).send("Unauthorized: Signature verification failed.");
  }
});


app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
