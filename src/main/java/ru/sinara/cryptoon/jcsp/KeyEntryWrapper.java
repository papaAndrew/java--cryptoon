package ru.sinara.cryptoon.jcsp;

import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCSP.JCSP;

import java.security.PrivateKey;
import java.security.cert.Certificate;

public class KeyEntryWrapper {
    private final JCPPrivateKeyEntry privateKeyEntry;
    private final PrivateKey privateKey;
    private final String privateKeyAlgorithm;

    public KeyEntryWrapper(JCPPrivateKeyEntry privateKeyEntry) {
        this.privateKeyEntry = privateKeyEntry;
        this.privateKey = privateKeyEntry.getPrivateKey();
        this.privateKeyAlgorithm = privateKey.getAlgorithm().toUpperCase();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public Certificate getCertificate() {
        return privateKeyEntry.getCertificate();
    }

    public Certificate[] getCertificateChain() {
        return privateKeyEntry.getCertificateChain();
    }

    public String getDigestOid() {
        return switch (privateKeyAlgorithm) {
            case JCSP.GOST_EL_2012_256_NAME, JCSP.GOST_DH_2012_256_NAME -> JCSP.GOST_DIGEST_2012_256_OID;
            case JCSP.GOST_EL_2012_512_NAME, JCSP.GOST_DH_2012_512_NAME -> JCSP.GOST_DIGEST_2012_512_OID;
            default -> JCSP.GOST_DIGEST_OID;
        };
    }

    public String getPublicKeyOid() {
        return switch (privateKeyAlgorithm) {
            case JCSP.GOST_EL_2012_256_NAME, JCSP.GOST_DH_2012_256_NAME -> JCSP.GOST_PARAMS_SIG_2012_256_KEY_OID;
            case JCSP.GOST_EL_2012_512_NAME, JCSP.GOST_DH_2012_512_NAME -> JCSP.GOST_PARAMS_SIG_2012_512_KEY_OID;
            default -> JCSP.GOST_EL_KEY_OID;
        };
    }

    public String getSignatureOid() {
        return switch (privateKeyAlgorithm) {
            case JCSP.GOST_EL_2012_256_NAME, JCSP.GOST_DH_2012_256_NAME -> JCSP.GOST_SIGN_2012_256_OID;
            case JCSP.GOST_EL_2012_512_NAME, JCSP.GOST_DH_2012_512_NAME -> JCSP.GOST_SIGN_2012_512_OID;
            default -> JCSP.GOST_EL_SIGN_OID;
        };
    }

    public String getAlgorithmName() {
        return switch (privateKeyAlgorithm) {
            case JCSP.GOST_EL_2012_256_NAME, JCSP.GOST_DH_2012_256_NAME -> JCSP.GOST_SIGN_2012_256_NAME;
            case JCSP.GOST_EL_2012_512_NAME, JCSP.GOST_DH_2012_512_NAME -> JCSP.GOST_SIGN_2012_512_NAME;
            default -> JCSP.GOST_EL_SIGN_NAME;
        };
    }
}
