package ru.sinara.cryptoon.core.jcsp.sign;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.sinara.cryptoon.jcsp.ActionFactoryImpl;
import ru.sinara.cryptoon.core.KeyStoreRegistrar;
import ru.sinara.cryptoon.jcsp.KeyEntryWrapper;
import ru.sinara.cryptoon.jcsp.sign.DigitalSignature;
import ru.sinara.cryptoon.jcsp.sign.JcspSignPkcsImpl;
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

    private static KeyEntryWrapper keyEntryWrapper;

    private DigitalSignature digitalSignature;



    @BeforeAll
    static void setUp() {
        KeyStore keyStore = KeyStoreRegistrar.initJcspKeyStore(KEYSTORE_PASSWORD.toCharArray());
        try {
            keyEntryWrapper = KeyStoreRegistrar.getKeyEntryWrapper(keyStore, KEY_ALIAS, KEY_PASSWORD.toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @BeforeEach
    void initTest() {
        digitalSignature = new JcspSignPkcsImpl(keyEntryWrapper);
    }


    @Test
    void createCadesSignature_Test() {
        assertNotNull(keyEntryWrapper);

        var bytes = digitalSignature.sign("Some data".getBytes());
        assertNotNull(bytes);
        assertEquals(723, bytes.length);

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
