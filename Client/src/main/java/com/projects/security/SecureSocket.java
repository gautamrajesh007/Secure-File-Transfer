package com.projects.security;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class SecureSocket {
    private static final String KEYSTORE_PATH = System.getProperty("user.dir") + "/Client/src/main/java/com/projects" +
            "/security/keystore/client.jks";
    private static final String TRUSTSTORE_PATH = System.getProperty("user.dir") + "/Client/src/main/java/com" +
            "/projects" +
            "/security/truststore/client-truststore.jks";

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
