package org.example.Crypto;

import org.example.Models.CryptoModel;
import org.example.Tools.FileTools;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Symmetric cryptography helper built around AES. It can derive a key from a password using PBKDF2,
 * encrypt data in AES/CBC/PKCS5Padding mode, and optionally wrap the symmetric key with an RSA public key.
 */
public class SymmetricCrypto {
    private SecretKey secretKey;
    public int keySize = 256;
    private CryptoModel cModel;

    // Vector d’inicialització (IV) fix per al mode CBC.
    private static final byte[] IV_PARAM = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,	0x0C, 0x0D, 0x0E, 0x0F};

    /**
     * Creates a new instance configuring AES key size and a file path hint for saving encrypted data.
     * Only 128 or 256-bit key sizes are accepted; otherwise the default 256 is used.
     *
     * @param keySize AES key size in bits (128 or 256)
     */
    public SymmetricCrypto(int keySize) {
        // Comprova que la mida de clau siga vàlida (128 o 256 bits)
        if (keySize == 256 || keySize == 128){
            this.keySize = keySize;
        }
    }

    /**
     * Creates a helper backed by an existing CryptoModel (to reuse an already encrypted payload and/or key).
     *
     * @param model model holding keys and encrypted data
     */
    public SymmetricCrypto(CryptoModel model){
        this.cModel = model; // Guarda el model amb dades o claus ja existents
    }

    /**
     * Derives an AES secret key from the provided password using PBKDF2WithHmacSHA256.
     * A random 16-byte salt and 65,536 iterations are used.
     *
     * @param password password to derive the key from
     * @throws NoSuchAlgorithmException if PBKDF2WithHmacSHA256 is not available
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private void CreateSymmetricSKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Genera un "salt" aleatori de 16 bytes
        byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);

        // Crea un generador de claus a partir de contrasenya amb PBKDF2 + HMAC-SHA256
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        // Es defineixen els paràmetres: contrasenya, salt, iteracions i mida de clau
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keySize);

        // Genera una clau temporal a partir dels paràmetres
        SecretKey tmp = factory.generateSecret(spec);

        // Converteix la clau temporal a una clau AES usable
        this.secretKey =  new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    /**
     * Encrypts the given data with an AES key derived from the provided password (PBKDF2) and stores
     * the result in this instance's CryptoModel for later retrieval/saving.
     *
     * @param password password used to derive the AES key
     * @param dataToEncrypt plaintext bytes to encrypt
     * @throws RuntimeException if an unexpected error occurs during encryption
     */
    public void Encrypt(String password, byte[] dataToEncrypt) {
        try {
            byte[] encryptedData = null;
            try {
                // Deriva la clau simètrica a partir de la contrasenya
                this.CreateSymmetricSKey(password);

                // Crea un xifrador amb AES en mode CBC i padding PKCS5
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

                // Assigna el vector d’inicialització (IV)
                IvParameterSpec iv = new IvParameterSpec(IV_PARAM);

                // Inicialitza el xifrador en mode ENCRYPT
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

                // Xifra les dades
                encryptedData = cipher.doFinal(dataToEncrypt);

                // Desa la clau i les dades xifrades en el model
                cModel = new CryptoModel(secretKey, encryptedData);
            } catch (Exception e) {
                // Si hi ha un error, es torna a llançar després
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Desa les dades xifrades al fitxer indicat
    public void SaveEncryptedData(String absPathEncryptedData) throws IOException {
        if (cModel != null){
            // Escriu les dades xifrades en un arxiu
            FileTools.writeFile(absPathEncryptedData, cModel.getEncryptedData());
        } else{
            throw new IOException("ERROR: S'ha d'encriptar primer el fitxer");
        }
    }

    /**
     * Encrypts data with the current AES key and wraps that AES key with the provided RSA public key.
     * The encrypted data and wrapped key are stored inside the current CryptoModel.
     *
     * @param publicKey RSA public key used to wrap the AES key
     * @param dataToEncrypt plaintext bytes to encrypt with AES
     */
    public void EncryptWrappedWithAsymmetric(PublicKey publicKey, byte[] dataToEncrypt){
        try {
            // Xifra les dades amb AES
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encMsg = cipher.doFinal(dataToEncrypt);

            // Xifra la clau simètrica amb RSA (wrap)
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, publicKey);
            byte[] encKey = cipher.wrap(secretKey);

            // Desa les dades xifrades i la clau xifrada dins del model
            cModel.setEncryptedData(encMsg);
            cModel.setEncryptedSKey(encKey);
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
    }

    // Desa tant les dades xifrades com la clau simètrica i la privada en fitxers
    public void SaveEncryptedDataAndKey(String absPathEncryptedData, String absPathEncryptedKey, String absPathPrivateKey){
        if (cModel.getPublicKey() != null
                && cModel.getSecretKey() != null){
            try{
                // Escriu cada element en el fitxer corresponent
                FileTools.writeFile(absPathEncryptedData, cModel.getEncryptedData());
                FileTools.writeFile(absPathEncryptedKey, cModel.getEncryptedSKey());
                FileTools.writeFile(absPathPrivateKey, cModel.getPrivateKey().getEncoded());

            } catch (IOException e) {}
        }
    }
}
