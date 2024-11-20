package com.projects.security;

import com.projects.security.handlers.EncryptedClientHandler;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.security.SecureRandom;

public class Main {
    public static void main(String[] args) {
        int port = 12345;

        try {
            // Load the server keystore and set up SSL context
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("../../../server.jks"), "password".toCharArray());

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, "password".toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());

            SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
            ServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(port);

            System.out.println("Secure server is running on port " + port);

            // Accept client connections and handle each in a new thread
            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                new Thread(new EncryptedClientHandler(clientSocket)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}