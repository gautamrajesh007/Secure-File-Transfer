package com.projects.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;

public class SecureServer {
    public static void main(String[] args) {
        // Register BouncyCastle as a security provider
        Security.addProvider(new BouncyCastleProvider());

        int port = 12345;

        try {
            // Load the server keystore
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("/Users/gautam/Security/Projects/TLS_Sim/Server/src/main/java/com/projects/security/keystores/server.jks"), "password".toCharArray());

            // KeyManagerFactory use the keystore for managing private keys and certificate
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, "password".toCharArray());

            // Initialized SSLContext with keyManagerFactory
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());

            // Create an SSL server socket and listen for connections
            SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(port);

            System.out.println("Secure server is running on port " + port);

            // Each new connection is handled in a separate thread using the EncryptedClientHandler class
            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                new Thread(new EncryptedClientHandler(clientSocket)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class EncryptedClientHandler implements Runnable {
    private final SSLSocket clientSocket;

    public EncryptedClientHandler(SSLSocket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        try (
                InputStream input = clientSocket.getInputStream();
                OutputStream output = clientSocket.getOutputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(input));
                PrintWriter writer = new PrintWriter(output, true)
        ) {
            String command = reader.readLine();
            if ("FILE_TRANSFER".equals(command)) {
                receiveEncryptedFile(input, writer);
            } else if ("MESSAGE".equals(command)) {
                String encryptedMessage = reader.readLine();
                String decryptedMessage = decryptMessage(encryptedMessage);
                System.out.println("Decrypted message: " + decryptedMessage);
                writer.println("Message received securely.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void receiveEncryptedFile(InputStream input, PrintWriter writer) throws Exception {
        // Wrap the input stream in a DataInputStream for easier handling of data(InputStream does provide methods to
        // read java primitive datatypes)
        DataInputStream dataInput = new DataInputStream(input);

        // Read the length of the encrypted AES key
        int keyLength = dataInput.readInt();
        byte[] encryptedKey = new byte[keyLength];
        dataInput.readFully(encryptedKey); // Read the full key
        System.out.println("Received Encrypted Key Length: " + encryptedKey.length);

        // Decrypt AES key using server's private EC key
        PrivateKey privateKey = loadPrivateKey();

        // Set up IES Parameters
        byte[] derivation = "DerivationKey".getBytes(); // Match the parameters used by the client
        byte[] encoding = "EncodingKey".getBytes();    // Match the parameters used by the client
        IESParameterSpec iesParams = new IESParameterSpec(derivation, encoding, 128);

        // Create a Cipher class instance for encryption and decryption
        Cipher eciesCipher = Cipher.getInstance("ECIES", "BC");
        eciesCipher.init(Cipher.DECRYPT_MODE, privateKey, iesParams);

        // Actual decryption of AES key from the ECIES cipher
        byte[] aesKeyBytes = eciesCipher.doFinal(encryptedKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Decrypt file data
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Adjust mode/padding if needed
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

        // Decrypting and writing the encrypted to new file on the server
        File file = new File("received_encrypted_file");
        try (FileOutputStream fileOut = new FileOutputStream(file);
             CipherInputStream cipherInput = new CipherInputStream(dataInput, aesCipher)) { // Use DataInputStream for seamless transition

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cipherInput.read(buffer)) != -1) {
                fileOut.write(buffer, 0, bytesRead);
            }
        }
        writer.println("Encrypted file received securely.");
    }

    private String decryptMessage(String encryptedMessage) throws Exception {
        // Placeholder for message decryption logic
        return "Decrypted message placeholder";
    }

    private PrivateKey loadPrivateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        System.out.println("Keystore jdk ---> " + keyStore);
        keyStore.load(new FileInputStream("/Users/gautam/Security/Projects/TLS_Sim/Server/src/main/java/com/projects/security/keystores/server.jks"), "password".toCharArray());
        return (PrivateKey) keyStore.getKey("server", "password".toCharArray());
    }
}