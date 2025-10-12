package org.example;

import junit.framework.TestCase;
import org.example.Crypto.AsymmetricCrypto;
import org.example.Models.CryptoModel;

/**
 * Tests for AsymmetricCrypto key generation.
 */
public class AsymmetricCryptoTest extends TestCase {

    public void testGenerateKeysDefaultAndCustom() {
        // Default-like (invalid override should keep internal default but still generate)
        AsymmetricCrypto a1 = new AsymmetricCrypto(1024); // below threshold per class logic
        CryptoModel m1 = a1.Generatekeys();
        assertNotNull(m1);
        assertNotNull(m1.getPrivateKey());
        assertNotNull(m1.getPublicKey());

        // Valid override
        AsymmetricCrypto a2 = new AsymmetricCrypto(2048);
        CryptoModel m2 = a2.Generatekeys();
        assertNotNull(m2);
        assertNotNull(m2.getPrivateKey());
        assertNotNull(m2.getPublicKey());
    }
}
