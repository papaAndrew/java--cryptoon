package ru.sinara.cryptoon.core;

import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCSP.JCSP;
import ru.sinara.cryptoon.core.jcsp.JcpKeyStoreProviderImpl;
import ru.sinara.cryptoon.exception.EntryUnavailableException;
import ru.sinara.cryptoon.exception.InitFailureException;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public interface KeyStoreProvider {
    static KeyStoreProvider createJcspKeyStoreProvider(String keystorePath, char[] password) throws InitFailureException {
        try (var fis = new FileInputStream(keystorePath)) {
            var keyStore = KeyStore.getInstance(JCSP.HD_STORE_NAME, JCSP.PROVIDER_NAME);
            keyStore.load(fis, password);
            return new JcpKeyStoreProviderImpl(keyStore);
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException | NoSuchProviderException e) {
            throw new InitFailureException("JCSP KeyStore create failed", e);
        }
    }

    KeyStore.PrivateKeyEntry getPrivateKeyEntry(String alias, KeyStore.ProtectionParameter protectedParameter) throws EntryUnavailableException;
}
