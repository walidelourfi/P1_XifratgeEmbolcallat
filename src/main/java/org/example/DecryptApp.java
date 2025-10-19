package org.example;

import org.example.Tools.FileTools;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public final class DecryptApp {
    // Igual que SymmetricCrypto, l'IV fix usat per a AES/CBC en aquest projecte
    private static final byte[] IV_PARAM = new byte[]{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    /**
     * Llegeix la clau privada (PKCS#8) des de fitxer i la retorna com a PrivateKey RSA.
     */
    private static PrivateKey readPrivateKeyFromFile(String absPathPrivateKey) throws Exception{
        byte[] pkcs8 =  Files.readAllBytes(Paths.get(absPathPrivateKey));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    /**
     * Desembolcalla (decrypt) la clau simètrica criptada amb RSA utilitzant la clau privada.
     * Retorna els bytes de la clau AES.
     */
    private static byte[] unwrapSymmetricKey(byte[] encryptedWrappedKey, PrivateKey privateKey) throws Exception{
        // Utilitzem OAEP amb SHA-256
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.UNWRAP_MODE, privateKey);
        return rsa.doFinal(encryptedWrappedKey);
    }

    /**
     * Desxifra el contingut AES/CBC/PKCS5Padding amb la clau simètrica donada.
     */
    private static byte[] decryptAesCbc(byte[] encryptedData, byte[] aesKeyBytes) throws Exception{
        SecretKey aes = new SecretKeySpec(aesKeyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(IV_PARAM);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Operació principal: llegeix els tres fitxers, desempaqueta la clau i desxifra les dades.
     * Retorna el contingut pla (no l'escriu al disc) perquè la crida pugui decidir què fer amb ell.
     */
    public static byte[] decryptFromFiles(String absPathEncryptedData, String absPathEncryptedKey, String absPathPrivateKey) throws Exception{
        byte[] encData = Files.readAllBytes(Paths.get(absPathEncryptedData));
        byte[] encKey = Files.readAllBytes(Paths.get(absPathEncryptedKey));
        PrivateKey priv = readPrivateKeyFromFile(absPathPrivateKey);

        byte[] aesKeyBytes = unwrapSymmetricKey(encKey, priv);
        byte[] plainTxt = decryptAesCbc(encData, aesKeyBytes);
        return plainTxt;
    }

    public static void main(String[] args) {
        if (args.length < 3){
            System.err.println("Ús: DecryptApp <encData> <encWrappedKey> <privateKeyPk8> [outputFile]");
            System.exit(2);
        }

        String absPathEncryptedData = args[0];
        String absPathEncryptedKey = args[1];
        String absPathPrivateKey = args[2];

        try {
            byte[] plain = decryptFromFiles(absPathEncryptedData, absPathEncryptedKey, absPathPrivateKey);

            if (args.length >= 4) {
                String out = args[3];
                FileTools.writeFile(out, plain);
                System.out.println("Desxifrat i guardat a: " + out);
            } else {
                System.out.println("Desxifrat correctament. Size(bytes): " + plain.length);
            }

        } catch (IOException io) {
            System.err.println("Error d'E/S: " + io.getMessage());
            System.exit(3);
        } catch (Exception ex) {
            System.err.println("Error en la desxifra: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(4);
        }
    }
}
