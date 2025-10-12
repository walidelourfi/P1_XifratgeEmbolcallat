package org.example;

import junit.framework.TestCase;
import org.example.Crypto.BaseCrypto;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Tests for BaseCrypto helpers.
 */
public class BaseCryptoTest extends TestCase {

    public void testAESKeygenValidSizes() {
        int[] sizes = {128, 192, 256};
        for (int size : sizes) {
            SecretKey k = BaseCrypto.keygenKeyGeneration(size);
            assertNotNull("SecretKey should be generated for size=" + size, k);
            assertEquals(size / 8, k.getEncoded().length);
        }
    }

    public void testPasswordKeyGeneration() {
        SecretKey k = BaseCrypto.passwordKeyGeneration("hola-món", 256);
        assertNotNull(k);
        assertEquals(32, k.getEncoded().length);
    }

    public void testEncryptECBConsistency() {
        SecretKey k = BaseCrypto.keygenKeyGeneration(128);
        byte[] msg = "test-message".getBytes();
        byte[] c1 = BaseCrypto.encryptData(k, msg);
        byte[] c2 = BaseCrypto.encryptData(k, msg);
        assertNotNull(c1);
        assertNotNull(c2);
        // ECB with same key and input should be deterministic
        assertTrue(Arrays.equals(c1, c2));
    }

    public void testEncryptCBCDeterminismWithFixedIV() {
        SecretKey k = BaseCrypto.keygenKeyGeneration(128);
        byte[] msg = "cbc-message".getBytes();
        byte[] c1 = BaseCrypto.encryptDataCBC(k, msg);
        byte[] c2 = BaseCrypto.encryptDataCBC(k, msg);
        assertNotNull(c1);
        assertNotNull(c2);
        // CBC uses a fixed IV in this project; encryption should be deterministic too
        assertTrue(Arrays.equals(c1, c2));
    }

    public void testRSAKeypairAndEncrypt() {
        KeyPair kp = BaseCrypto.randomGenerate(2048);
        assertNotNull(kp);
        PublicKey pub = kp.getPublic();
        byte[] ct = BaseCrypto.encryptData("hello".getBytes(), pub);
        assertNotNull(ct);
        assertTrue(ct.length > 0);
    }

    public void testSignAndValidate() {
        KeyPair kp = BaseCrypto.randomGenerate(2048);
        byte[] data = "firmar".getBytes();
        byte[] sig = BaseCrypto.signData(data, kp.getPrivate());
        assertNotNull(sig);
        assertTrue(BaseCrypto.validateSignature(data, sig, kp.getPublic()));
        // Modify data -> validation should fail
        assertFalse(BaseCrypto.validateSignature("firmar!".getBytes(), sig, kp.getPublic()));
    }

    public void testEncryptWrappedData() {
        KeyPair kp = BaseCrypto.randomGenerate(2048);
        byte[][] out = BaseCrypto.encryptWrappedData("wrap".getBytes(), kp.getPublic());
        assertNotNull(out);
        assertEquals(2, out.length);
        assertNotNull(out[0]);
        assertNotNull(out[1]);
        assertTrue(out[0].length > 0);
        assertTrue(out[1].length > 0);
    }
}
