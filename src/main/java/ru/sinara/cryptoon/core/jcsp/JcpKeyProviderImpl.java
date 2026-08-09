package ru.sinara.cryptoon.core.jcsp;

import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.sinara.cryptoon.core.KeyStoreProvider;
import ru.sinara.cryptoon.core.KeyProvider;

import java.security.*;
import java.security.cert.Certificate;

public class JcpKeyProviderImpl implements KeyProvider {
    protected final KeyStoreProvider keyStoreProvider;
    protected final KeyStore.ProtectionParameter protectedParameter;
    protected final JCPPrivateKeyEntry privateKeyEntry;

    public JcpKeyProviderImpl(KeyStoreProvider keyStoreProvider, String alias, char[] password)
            throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException
    {
        this.keyStoreProvider = keyStoreProvider;
        this.protectedParameter = new KeyStore.PasswordProtection(password);
    }


    @Override
    public PrivateKey getPrivateKey() {
        var privateKeyEntry = keyStoreProvider.getPrivateKeyEntry(alias, protectedParameter);
        return privateKeyEntry.getPrivateKey();
    }

    @Override
    public Certificate getCertificate() {
        return privateKeyEntry.getCertificate();
    }
}
