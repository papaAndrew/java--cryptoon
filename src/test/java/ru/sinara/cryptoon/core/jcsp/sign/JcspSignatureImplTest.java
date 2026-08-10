package ru.sinara.cryptoon.core.jcsp.sign;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.sinara.cryptoon.jcsp.JcspOperationFactoryImpl;
import ru.sinara.cryptoon.core.KeyStoreRegistrar;
import ru.sinara.cryptoon.core.SignAlgorithm;
import ru.sinara.cryptoon.jcsp.sign.DigitalSignature;
import wiremock.com.google.common.io.Files;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static wiremock.org.hamcrest.MatcherAssert.assertThat;

class JcspSignatureImplTest {

    private static final String KEYSTORE_PATH = "/var/opt/cprocsp/keys/papa";
    private static final String KEYSTORE_PASSWORD = "";
    public static final String KEY_ALIAS = "myTest";
    public static final String KEY_PASSWORD = "123456";

    private static KeyStore keyStore;
    private static KeyStore.PasswordProtection keyPassword;

    private DigitalSignature digitalSignature;


    @BeforeAll
    static void setUp() {
        keyStore = KeyStoreRegistrar.createJcspKeyStore(KEYSTORE_PATH, KEYSTORE_PASSWORD.toCharArray());
        keyPassword = new KeyStore.PasswordProtection(KEY_PASSWORD.toCharArray());
    }

    @BeforeEach
    void initTest() {
        JcspOperationFactoryImpl jcspOperationFactory = new JcspOperationFactoryImpl(keyStore);
        digitalSignature = jcspOperationFactory.createJcspDigitalSignature(SignAlgorithm.SIGN_2012_256, KEY_ALIAS, KEY_PASSWORD.toCharArray());
    }


    @Test
    void createCadesSignature_Test() {
        var bytes = digitalSignature.signCades("Some data".getBytes());
        assertNotNull(bytes);
        assertEquals(64, bytes.length);

        System.out.println("bytes = " + new String(bytes));

        var enc = Base64.getEncoder().encode(bytes);
        System.out.println("enc = " + new String(enc));

        try {
            Files.write(enc, new File("src/test/resources/some_data.sig"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
