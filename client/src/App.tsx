//Digital Signature Scheme with SHA-256 and RSA is implemented to ensure data
//integrity (no tampering of client or server communication)

import React, { useEffect, useState, useCallback} from "react";


const API_URL = "http://localhost:8080";

function App() {
  const [data, setData] = useState<string>("");
  
  //state variables for client public, private keys
  const [publicKey,setPublicKey] = useState<string>("");
  const [privateKey,setPrivateKey] = useState<string>("");


  //generate client-side public,private keys
  async function generateKeyPair() {
    let keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: {name: "SHA-256"},
      },
      true,
      ["sign", "verify"]
    );
    return keyPair;
  }

  async function exportPublicKey(keyPair) {
    let exportedKey = await window.crypto.subtle.exportKey(
      "spki", 
      keyPair.publicKey
    );
    // Convert buffer to something usable
    let exportedAsBase64 = btoa(String.fromCharCode.apply(null, new Uint8Array(exportedKey)));
    return exportedAsBase64;
  }
  
  async function exportPrivateKey(keyPair) {
    let exportedKey = await window.crypto.subtle.exportKey(
      "pkcs8", 
      keyPair.privateKey
    );
    // Convert buffer
    let exportedAsBase64 = btoa(String.fromCharCode.apply(null, new Uint8Array(exportedKey)));
    return exportedAsBase64;
  }

  //initialize client public,private keys
  async function setUpKeys(){
    let keyPairT = await generateKeyPair();
    let publicKeyT = await exportPublicKey(keyPairT);
    let privateKeyT = await exportPrivateKey(keyPairT);
    setPublicKey(publicKeyT);
    setPrivateKey(privateKeyT);
  }
  setUpKeys();



  const getData = useCallback(async () => {
        const response = await fetch(API_URL);
        const { message } = await response.json();
    
        setData(message); // set the data from the server
  },[]);




  const updateData = async () => {
    // Convert the message string to an ArrayBuffer
    let encoder = new TextEncoder();
    let encodedMessage = encoder.encode(data);
  
  
    // Convert the private key back from base64
    let rawPrivateKey = atob(privateKey);
    let uint8ArrayPrivateKey = new Uint8Array(rawPrivateKey.split("").map(char => char.charCodeAt(0)));
  
    // Import the private key
    let importedPrivateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      uint8ArrayPrivateKey,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: {name: "SHA-256"}
      },
      false,
      ["sign"]
    );
  
    // Sign the hash with the private key to create the signature
    let signatureBuffer = await window.crypto.subtle.sign(
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: {name: "SHA-256"} 
      },
      importedPrivateKey,
      encodedMessage  
    );

  
    // Convert the signature to Base64 to send it as a string
    let signature = btoa(String.fromCharCode.apply(null, new Uint8Array(signatureBuffer)));
  
    // Construct the data to send
    const sent_data = {
      message: data,
      signature: signature,
      public_key: publicKey
    };
  
    // Send the data to the server
    await fetch(API_URL, {
      method: "POST",
      body: JSON.stringify({ sent_data }),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    });
  
    // Refresh data
    await getData();
  };
  

  const verifyData = async () => {
    try {
      const response = await fetch(API_URL);
      const { message,  signature, publicKey } = await response.json();

      //trim excess on public key to make bae64 data type
      const trimmedPublicKey = publicKey
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s+/g, '');

      // Convert the message string to an ArrayBuffer
      let encoder = new TextEncoder();
      let encodedMessage = encoder.encode(message);

      // Import the public key
      const importedPublicKey = await window.crypto.subtle.importKey(
          "spki",
          _base64ToArrayBuffer(trimmedPublicKey), // Convert Base64 to ArrayBuffer
          {
              name: "RSASSA-PKCS1-v1_5",
              hash: { name: "SHA-256" },
          },
          true,
          ["verify"] 
      );

      // Verify the signature
      const isVerified = await window.crypto.subtle.verify(
          {
              name: "RSASSA-PKCS1-v1_5",
              hash: { name: "SHA-256" },
          },
          importedPublicKey,
          _base64ToArrayBuffer(signature), // Convert Base64 to ArrayBuffer
          encodedMessage
      );

      console.log("Signature verification result:", isVerified);
      // set the data from the server
      setData(message); 
  } catch (error) {
      console.error("Error in getData:", error);
  }
  };

    // Helper function to convert Base64 to ArrayBuffer
  function _base64ToArrayBuffer(base64) {
    try {
        var binary_string = window.atob(base64.trim()); 
        var len = binary_string.length;
        var bytes = new Uint8Array(len);
        for (var i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (e) {
        console.error("Failed to decode Base64 string:", base64, "Error:", e);
        throw e; 
    }
  }



  useEffect(() => {
    getData();
  }, [getData]);


  return (
    <div
      style={{
        width: "100vw",
        height: "100vh",
        display: "flex",
        position: "absolute",
        padding: 0,
        justifyContent: "center",
        alignItems: "center",
        flexDirection: "column",
        gap: "20px",
        fontSize: "30px",
      }}
    >
      <div>Saved Data</div>
      <input
        style={{ fontSize: "30px" }}
        type="text"
        value={data}
        onChange={(e) => setData(e.target.value)}
      />

      <div style={{ display: "flex", gap: "10px" }}>
        <button style={{ fontSize: "20px" }} onClick={updateData}>
          Update Data
        </button>
        <button style={{ fontSize: "20px" }} onClick={verifyData}>
          Verify Data
        </button>
      </div>
    </div>
  );
}

export default App;
