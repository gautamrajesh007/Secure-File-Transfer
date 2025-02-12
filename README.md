# TLS Simulation

This project demonstrates the simulation of file transfer using TLS with addition of malware scanning using 
Java and VirusTotal APIs.
It includes both 
client and 
server 
components.

## Prerequisites

- JDK 21
- Maven
- Dotenv-Java
- Keytool (included in JDK)
- Jackson JSON Library
- Apache HttpComponents Client

## Steps to Generate and Add Keys and Certificates

### 1. Generate an RSA Keypair for the Server

```sh
keytool -genkeypair -alias server -keyalg RSA -keysize 4096 -sigalg SHA256withRSA \
        -keystore server.jks -storepass password -keypass password \
        -dname "CN=SecureServer, OU=TLS, O=MyOrg, L=City, S=State, C=IN"
```

### 2. Export the Server Certificate

```sh
keytool -exportcert -alias server -keystore server.jks -file server_cert.crt -storepass password
```

### 3. Generate an RSA Keypair for the Client

```sh
keytool -genkeypair -alias client -keyalg RSA -keysize 4096 -sigalg SHA256withRSA \
        -keystore client.jks -storepass password -keypass password \
        -dname "CN=SecureClient, OU=TLS, O=MyOrg, L=City, S=State, C=IN"
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

### 7. Import certificates to the truststore

- Instead of modifying $JAVA_HOME/lib/security/cacerts, create a dedicated truststore.
- This avoids system-wide risks.

```sh
keytool -importcert -alias server_cert -file server_cert.crt -keystore client-truststore.jks -storepass password
```

```sh
keytool -importcert -alias client_cert -file client_cert.crt -keystore server-truststore.jks -storepass password
```

## Project Structure

- `Client/`: Contains the client-side code.
- `Server/`: Contains the server-side code.

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

## Tips

- Enhance the security by removing the hardcoded shared key seed value.
- Use env to abstract the sensitive values.
- Use a secure random number generator.

## License

This project is licensed under the MIT License.