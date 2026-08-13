package ru.sinara.cryptoon.jcsp;

import ru.sinara.cryptoon.core.KeyStoreRegistrar;
import ru.sinara.cryptoon.exception.KeyEntryFailedException;
import ru.sinara.cryptoon.exception.KeyStoreFailedException;
import ru.sinara.cryptoon.jcsp.sign.ActionFactory;
import ru.sinara.cryptoon.jcsp.sign.DigitalSignature;
import ru.sinara.cryptoon.jcsp.sign.JcspSignPkcsImpl;

import java.security.*;

public class ActionFactoryImpl implements ActionFactory {
    protected final KeyStore keyStore;

    public ActionFactoryImpl(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @Override
    public DigitalSignature createPkcsDetached(String alias, char[] password) {
        KeyEntryWrapper keyEntryWrapper;
        try {
            keyEntryWrapper = KeyStoreRegistrar.getKeyEntryWrapper(keyStore, alias, password);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new KeyEntryFailedException("Key entry unavailable", e);
        }
        if (keyEntryWrapper != null) {
            return new JcspSignPkcsImpl(keyEntryWrapper);
        }
        throw new KeyEntryFailedException("Key entry not found");
    }
}
