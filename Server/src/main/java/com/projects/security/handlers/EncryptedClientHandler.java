package com.projects.security.handlers;

import javax.net.ssl.SSLSocket;
import java.io.*;

public class EncryptedClientHandler implements Runnable{
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
            PrintWriter writer = new PrintWriter(output, true);
        ) {
            String command = reader.readLine();
            if ("FILE_TRANSFER".equals(command)) {
                // Handle file transfer
                ReceiveEncryptedFile receiveFile = new ReceiveEncryptedFile(input, writer);
                receiveFile.receiveEncryptedFile();
            } else if ("MESSAGE".equals(command)) {
                // Handle message
                String encryptedMessage = reader.readLine();
                String decryptedMessage = decryptMessage(encryptedMessage);
                System.out.println("Decrypted message: " + decryptedMessage);
                writer.println("Message received securely.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String decryptMessage(String encryptedMessage) throws Exception {
        // Implement decryption logic decryption of message --> currently using a string placeholder
        return "Decrypted message placeholder";
    }
}
