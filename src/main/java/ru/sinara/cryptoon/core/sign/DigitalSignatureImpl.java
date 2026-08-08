package ru.sinara.cryptoon.core.sign;

import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCSP.JCSP;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;

public class DigitalSignatureImpl implements DigitalSignature {

    private final KeyStore keyStore;
    private final char[] password;
    private final String alias;

    public DigitalSignatureImpl(String keystorePath, char[] password, String alias) throws Exception {
        this.password = password;
        this.alias = alias;
        this.keyStore = KeyStore.getInstance(JCSP.HD_STORE_NAME, JCSP.PROVIDER_NAME);
        try (var fis = new java.io.FileInputStream(keystorePath)) {
            keyStore.load(fis, password);
        }
    }

    @Override
    public byte[] sign(byte[] data) throws Exception {
        final String message = "Message for signature";

        PrivateKey privateKey;
        PublicKey publicKey;

        KeyStore.ProtectionParameter protectedParam =
                new KeyStore.PasswordProtection(password);

        JCPPrivateKeyEntry entry = (JCPPrivateKeyEntry)
                keyStore.getEntry(alias, protectedParam);

        privateKey = entry.getPrivateKey();

        Signature signer = Signature.getInstance(
                "CADES-BES", JCSP.PROVIDER_NAME);

        signer.initSign(privateKey);
        signer.update(message.getBytes());

        return signer.sign();
}
}
