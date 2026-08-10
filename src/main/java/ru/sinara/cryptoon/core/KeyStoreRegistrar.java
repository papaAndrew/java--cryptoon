package ru.sinara.cryptoon.core;

import ru.CryptoPro.JCP.Util.JCPInit;
import ru.CryptoPro.JCSP.JCSP;
import ru.sinara.cryptoon.exception.InitFailureException;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class KeyStoreRegistrar {

    public static KeyStore createJcspKeyStore(String keystorePath, char[] password) throws InitFailureException {
        JCPInit.initProviders(true);
        try {
            var keyStore = KeyStore.getInstance(JCSP.HD_STORE_NAME, JCSP.PROVIDER_NAME);
            keyStore.load(null, password);
            return keyStore;
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException | NoSuchProviderException e) {
            throw new InitFailureException("JCSP KeyStore create failed", e);
        }
    }
}
