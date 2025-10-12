package org.example.Crypto;

import org.example.Models.CryptoModel;

import java.security.*;

/**
 * Utility class for generating asymmetric RSA key pairs and packaging them into a CryptoModel.
 * <p>
 * Default key length is 4096 bits. The constructor allows overriding the key size when it is greater than
 * 1028 and even (bit-lengths are typically multiples of 8). Errors are written to stderr in Catalan/Spanish
 * as per the project's existing conventions.
 * </p>
 */
public class AsymmetricCrypto {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private int keyLen = 4096;
    private CryptoModel cModel;

    /**
     * Creates a new AsymmetricCrypto helper with a desired RSA key length.
     * The key length is only applied if it is greater than 1028 and even; otherwise the default (4096) is kept.
     *
     * @param keyLen desired key length in bits (e.g., 2048, 3072, 4096)
     */
    public AsymmetricCrypto(int keyLen) {
        // Verifiquem la longitud de la clau sigui mes gran de 1028 per seguretat
        // i sigui par per a prevenir errors al tratarse de bits.
        if (keyLen > 1028 && keyLen % 2 == 0 ){
            this.keyLen = keyLen;
        }
    }

    /**
     * Generates an RSA {@link KeyPair} using the configured key length.
     *
     * @return the generated key pair, or null if the generator is unavailable
     * @throws NoSuchAlgorithmException if the RSA algorithm is not supported
     */
    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keyLen);
            return keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return null;
    }

    /**
     * Generates an RSA key pair and wraps it in a {@link CryptoModel}.
     *
     * @return a CryptoModel containing the private and public keys, or null if generation failed
     */
    public CryptoModel Generatekeys(){
        try {
            KeyPair keys = generateKeyPair();
            if (keys != null) {
                return new CryptoModel(keys.getPrivate(), keys.getPublic());
            } else{
                throw new Exception();
            }
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return null;
    }
}
