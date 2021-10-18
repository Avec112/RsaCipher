package io.avec.keypairexperiment;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class RsaCipherTest {

    private RsaCipher rsaCipher;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        rsaCipher = new RsaCipher();
        keyPair = rsaCipher.generateKeyPair();
    }

    @Test
    void generateKeyPair() {

        final PublicKey publicKey = keyPair.getPublic();

        assertEquals("RSA", publicKey.getAlgorithm());
        assertEquals("X.509", publicKey.getFormat());

        final PrivateKey privateKey = keyPair.getPrivate();

        assertEquals("RSA", privateKey.getAlgorithm());
        assertEquals("PKCS#8", privateKey.getFormat());
    }

    @Test
    void encryptAndDecrypt() throws Exception {
        final String expectedPlainText = "Secret text";

        // encrypt
        final String cipherText = rsaCipher.rsaEncrypt(expectedPlainText, keyPair.getPublic());
        assertNotEquals(expectedPlainText, cipherText);

        // decrypt
        final String plainText = rsaCipher.rsaDecrypt(cipherText, keyPair.getPrivate());
        assertEquals(expectedPlainText, plainText);

    }
}