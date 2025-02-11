package com.projects.security;

import io.github.cdimascio.dotenv.Dotenv;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;

public class ClientHandler implements Runnable {
    private static final Dotenv env = Dotenv.load();
    private static final String KEYSTOREPATH = System.getProperty("user.dir") + env.get("KEYSTOREPATH");
    private final SSLSocket clientSocket;

    public ClientHandler(SSLSocket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @SuppressWarnings("CallToPrintStackTrace")
    @Override
    public void run() {
        try (
                InputStream input = clientSocket.getInputStream();
                OutputStream output = clientSocket.getOutputStream();
                DataInputStream reader = new DataInputStream(input);
                PrintWriter writer = new PrintWriter(output, true)
        ) {
            receiveFile(reader, writer);

        } catch (Exception e) {
            System.err.println("Error processing client request: " + e.getMessage());
            e.printStackTrace();
        }

        finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error closing client socket: " + e.getMessage());
                e.printStackTrace();
            }
        }

    }

    private void receiveFile(DataInputStream dataInput, PrintWriter writer) throws Exception{
        // Read file name first
        String fileName = dataInput.readUTF();
        System.out.println("Receiving file: " + fileName);

        // Read the length of the encrypted AES key
        int keyLength = dataInput.readInt();
        byte[] encryptedKey = new byte[keyLength];
        dataInput.readFully(encryptedKey);
        System.out.println("Received Encrypted Key Length: " + encryptedKey.length);

        // Decrypt AES key using server's private RSA key
        PrivateKey privateKey = loadPrivateKey();

        // Create a Cipher class instance for encryption and decryption
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Actual decryption of AES key from the RSA cipher
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Decrypt file data
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

        // Decrypting and writing the encrypted to new file on the server
        ByteArrayOutputStream tempBuffer = new ByteArrayOutputStream();
        try (FileOutputStream fileOut = new FileOutputStream(System.getProperty("user.dir") + "/Server/src/main" +
                "/resources/" + fileName);
             // Using CipherInputStream with the AES cipher to decrypt on the fly
             CipherInputStream cipherInput = new CipherInputStream(dataInput, aesCipher)) {

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cipherInput.read(buffer)) != -1) {
                tempBuffer.write(buffer, 0, bytesRead);
            }
        }
        writer.println("Encrypted file received securely.");

        File tempFile = new File(System.getProperty("user.dir") + "/Server/src/main" +
                "/resources/temp_received_" + fileName);
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            fos.write(tempBuffer.toByteArray());
        }

        // Scan the file with VirusTotal before saving it permanently
        if (!MalwareScanner.scanFile(tempFile.getAbsolutePath())) {
            System.out.println("File is malicious! Rejecting.");
            writer.println("File rejected due to malware.");
            tempFile.delete(); // Delete the temp file
            return;
        }

        // If clean, save the file permanently
        File finalFile = new File(System.getProperty("user.dir") + "/Server/src/main" +
                "/resources/" + fileName);
        tempFile.renameTo(finalFile);
        System.out.println("File --> " + tempFile.getName() + " received and stored safely.");
    }

    private static PrivateKey loadPrivateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(KEYSTOREPATH), "password".toCharArray());
        return (PrivateKey) keyStore.getKey("server", "password".toCharArray());
    }
}
