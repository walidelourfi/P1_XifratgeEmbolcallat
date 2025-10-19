package org.example.Crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Base cryptographic helper methods used by tests and higher-level helpers.
 */
public final class BaseCrypto {

    private static final byte[] IV_PARAM = new byte[]{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    private BaseCrypto() {}

    // --- Symmetric key helpers ---

    public static SecretKey keygenKeyGeneration(int keySize) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(keySize);
            return kg.generateKey();
        } catch (Exception e) {
            return null;
        }
    }

    public static SecretKey passwordKeyGeneration(String password, int keySize) {
        try {
            // PBKDF2 with HMAC-SHA256
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            // For the purposes of tests we only care about key length; use a fixed salt to avoid needing to carry it around
            byte[] salt = "p1walid-fixed-salt".getBytes();
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keySize);
            byte[] enc = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(enc, "AES");
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] encryptData(SecretKey key, byte[] data) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            return c.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] encryptDataCBC(SecretKey key, byte[] data) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV_PARAM));
            return c.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    // --- Asymmetric helpers ---

    public static KeyPair randomGenerate(int keySize) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] encryptData(byte[] data, PublicKey pub) {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.ENCRYPT_MODE, pub);
            return c.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] signData(byte[] data, PrivateKey priv) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(priv);
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(pub);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Encrypts data with a fresh AES-128 key using CBC and returns a 2-item array:
     * [0] ciphertext, [1] RSA-wrapped AES key bytes.
     */
    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        try {
            SecretKey aes = keygenKeyGeneration(128);
            byte[] ct = encryptDataCBC(aes, data);
            Cipher w = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            w.init(Cipher.WRAP_MODE, pub);
            byte[] wrapped = w.wrap(aes);
            return new byte[][]{ct, wrapped};
        } catch (Exception e) {
            return null;
        }
    }
}
