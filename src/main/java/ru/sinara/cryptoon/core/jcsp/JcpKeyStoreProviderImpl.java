package ru.sinara.cryptoon.core.jcsp;

import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.sinara.cryptoon.core.KeyStoreProvider;
import ru.sinara.cryptoon.exception.EntryUnavailableException;

import java.security.*;

public class JcpKeyStoreProviderImpl implements KeyStoreProvider {
    protected final KeyStore keyStore;

    public JcpKeyStoreProviderImpl(KeyStore keyStore) {
        this.keyStore = keyStore;
    }


    @Override
    public KeyStore.PrivateKeyEntry getPrivateKeyEntry(String alias, KeyStore.ProtectionParameter protectedPassword) throws EntryUnavailableException
    {
        try {
            var entry = (JCPPrivateKeyEntry)keyStore.getEntry(alias, protectedPassword;
            return (KeyStore.PrivateKeyEntry) entry;
//            return  keyStore.getEntry(alias, protectedPassword);
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw new EntryUnavailableException("Private key not available for alias " + alias, e);
        }
    }

    }
}
