package org.example.Models;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Data transfer object used across the project to carry cryptographic material and results.
 * It can hold symmetric and asymmetric keys, encrypted payloads, and a wrapped symmetric key.
 */
public class CryptoModel {
    public SecretKey secretKey;
    public PublicKey publicKey;
    public PrivateKey privateKey;
    public byte[] encryptedData;
    public byte[] encryptedSKey;

    /**
     * Full constructor to populate the model with symmetric and asymmetric keys and encrypted data.
     */
    public CryptoModel(SecretKey secretKey, PublicKey publicKey, PrivateKey privateKey, byte[] encryptedData) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.encryptedData = encryptedData;
    }

    /**
     * Constructor for symmetric encryption results.
     */
    public CryptoModel(SecretKey secretKey, byte[] encryptedData) {
        this.secretKey = secretKey;
        this.encryptedData = encryptedData;
    }

    /**
     * Constructor variant carrying private/public keys and encrypted data.
     */
    public CryptoModel(PrivateKey privateKey, byte[] encryptedData, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.encryptedData = encryptedData;
        this.publicKey = publicKey;
    }

    /**
     * Constructor to carry an asymmetric key pair only.
     */
    public CryptoModel(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * @return symmetric AES key (may be null)
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /**
     * @return RSA public key (may be null)
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * @return RSA private key (may be null)
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * @return encrypted payload bytes (may be null)
     */
    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData;
    }

    /**
     * @return wrapped/encrypted symmetric key bytes (may be null)
     */
    public byte[] getEncryptedSKey() {
        return encryptedSKey;
    }

    public void setEncryptedSKey(byte[] encryptedSKey) {
        this.encryptedSKey = encryptedSKey;
    }
}
