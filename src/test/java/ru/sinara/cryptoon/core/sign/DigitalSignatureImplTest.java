package ru.sinara.cryptoon.core.sign;

import static org.junit.jupiter.api.Assertions.*;
import static wiremock.org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.CryptoPro.JCP.Util.JCPInit;
import ru.sinara.cryptoon.core.KeyProvider;
import ru.sinara.cryptoon.core.jcsp.JcpKeyProviderImpl;
import ru.sinara.cryptoon.core.KeyStoreProvider;
import ru.sinara.cryptoon.core.jcsp.JcpKeyStoreProviderImpl;
import ru.sinara.cryptoon.core.jcsp.sign.JcspSignatureImpl;
import ru.sinara.cryptoon.core.jcsp.SignAlgorithm;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

class DigitalSignatureImplTest {

    private static final String KEYSTORE_PATH = "keystore.jks";
    private static final String KEYSTORE_PASSWORD = "password";

    private KeyProvider keyProvider;
    private KeyStoreProvider keyStoreProvider;

    @BeforeAll
    static void setUp() {
        JCPInit.initProviders(true);
    }

    @BeforeEach
    void initTest() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        keyStoreProvider = JcpKeyStoreProviderImpl.create(KEYSTORE_PATH, KEYSTORE_PASSWORD.toCharArray());
        keyProvider = new JcpKeyProviderImpl(keyStore);
    }

    @Test
    void sign() {
        JcspSignatureImpl signature = new JcspSignatureImpl(SignAlgorithm.SIGN_2012_256, keyProvider);
        byte[] result;
//        = signature.sign("test".getBytes());
        assertNotNull(result);
        assertTrue(result.length > 0);
    }
}
