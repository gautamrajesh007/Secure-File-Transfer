# TLS Simulation

This project demonstrates the simulation of TLS in HTTPS using Java and Maven. It includes both client and server components.

## Prerequisites

- Java Development Kit (JDK)
- Maven
- Keytool (included in JDK)
- BouncyCastle(Open-source cryptographic APIs)

## Steps to Generate and Add Keys and Certificates

### 1. Generate an ECDSA Keypair for the Server

```sh
keytool -genkeypair -alias server -keyalg EC -keysize 256 -sigalg SHA256withECDSA \
        -keystore server.jks -storepass password -keypass password \
        -dname "CN=SecureServer, OU=Crypto, O=MyOrg, L=City, S=State, C=IN"
```

### 2. Export the Server Certificate

```sh
keytool -exportcert -alias server -keystore server.jks -file server_cert.crt -storepass password
```

### 3. Generate an ECDSA Keypair for the Client

```sh
keytool -genkeypair -alias client -keyalg EC -keysize 256 -sigalg SHA256withECDSA \
        -keystore client.jks -storepass password -keypass password \
        -dname "CN=SecureClient, OU=Crypto, O=MyOrg, L=City, S=State, C=IN"
```

### 4. Export the Client Certificate

```sh
keytool -exportcert -alias client -keystore client.jks -file client_cert.crt -storepass password
```

### 5. Import the Server Certificate into the Client Keystore

```sh
keytool -importcert -alias server_cert -file server_cert.crt \
        -keystore client.jks -storepass password
```

### 6. Import the Client Certificate into the Server Keystore

```sh
keytool -importcert -alias client_cert -file client_cert.crt \
        -keystore server.jks -storepass password
```

### 7. Import Server Certificate into Client Truststore

```sh
sudo keytool -import -alias server -file server_cert.crt -keystore $JAVA_HOME/lib/security/cacerts -storepass password
```

### 8. Import Client Certificate into Server Truststore

```sh
sudo keytool -import -alias client -file client_cert.crt -keystore $JAVA_HOME/lib/security/cacerts -storepass password
```

## Project Structure

- `client/`: Contains the client-side code.
- `server/`: Contains the server-side code.

## Building the Project

Navigate to the root directory of the project and run:

```sh
mvn clean install
```

## Running the Project

### Server

Navigate to the `server` directory and run:

```sh
mvn exec:java -Dexec.mainClass="com.myorg.server.ServerMain"
```

### Client

Navigate to the `client` directory and run:

```sh
mvn exec:java -Dexec.mainClass="com.myorg.client.ClientMain"
```

## License

This project is licensed under the MIT License.