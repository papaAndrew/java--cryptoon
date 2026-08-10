package ru.sinara.cryptoon.jcsp;

import ru.sinara.cryptoon.core.SignAlgorithm;
import ru.sinara.cryptoon.jcsp.sign.DigitalSignature;
import ru.sinara.cryptoon.jcsp.sign.JcspSignatureImpl;
import ru.sinara.cryptoon.exception.EntryUnavailableException;

import java.security.*;

public class JcspOperationFactoryImpl {
    protected final KeyStore keyStore;

    public JcspOperationFactoryImpl(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public DigitalSignature createJcspDigitalSignature(SignAlgorithm signAlgorithm, String alias, char[] password) {
        KeyStore.ProtectionParameter protectedPassword = new KeyStore.PasswordProtection(password);
        try {
            return new JcspSignatureImpl(signAlgorithm, keyStore, alias, protectedPassword);
        } catch (NoSuchAlgorithmException | InvalidKeyException | KeyStoreException | UnrecoverableEntryException | NoSuchProviderException e) {
            throw new EntryUnavailableException("Failed to load keystore", e);
        }

    }
}
