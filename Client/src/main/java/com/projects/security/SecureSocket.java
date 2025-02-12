package com.projects.security;

import io.github.cdimascio.dotenv.Dotenv;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class SecureSocket {
    private static final Dotenv env = Dotenv.load();
    private static final String KEYSTORE_PATH = System.getProperty("user.dir") + env.get("KEYSTORE_PATH");
    private static final String TRUSTSTORE_PATH = System.getProperty("user.dir") + env.get("TRUSTSTORE_PATH");

    public SecureSocket() {}

    private static SSLSocketFactory sslSocketFactory() throws KeyStoreException, IOException,
            CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(KEYSTORE_PATH), "password".toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, "password".toCharArray());

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream(TRUSTSTORE_PATH), "password".toCharArray());

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

        return sslContext.getSocketFactory();
    }

    public static SSLSocketFactory getSSLSocketFactory() throws UnrecoverableKeyException, CertificateException,
            KeyStoreException, IOException, NoSuchAlgorithmException, KeyManagementException {
        return sslSocketFactory();
    }
}
