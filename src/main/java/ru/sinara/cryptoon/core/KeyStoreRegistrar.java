package ru.sinara.cryptoon.core;

import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCP.Util.JCPInit;
import ru.CryptoPro.JCSP.JCSP;
import ru.sinara.cryptoon.exception.KeyStoreFailedException;
import ru.sinara.cryptoon.jcsp.KeyEntryWrapper;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class KeyStoreRegistrar {

    public static KeyStore initJcspKeyStore(char[] password) throws KeyStoreFailedException {
        JCPInit.initProviders(true);
        try {
            var keyStore = KeyStore.getInstance(JCSP.HD_STORE_NAME, JCSP.PROVIDER_NAME);
            keyStore.load(null, password);
            return keyStore;
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException | NoSuchProviderException e) {
            throw new KeyStoreFailedException("JCSP KeyStore create failed", e);
        }
    }

    public static KeyEntryWrapper getKeyEntryWrapper(KeyStore keyStore, String alias, char[] password)
            throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        if (!keyStore.isKeyEntry(alias)) {
            return null;
        }
        KeyStore.ProtectionParameter protectedParam = new KeyStore.PasswordProtection(password);
        JCPPrivateKeyEntry entry = (JCPPrivateKeyEntry) keyStore.getEntry(alias, protectedParam);
        return new KeyEntryWrapper(entry);
    }
}
