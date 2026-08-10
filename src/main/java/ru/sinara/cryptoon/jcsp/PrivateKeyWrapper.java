package ru.sinara.cryptoon.jcsp;

import ru.CryptoPro.JCSP.JCSP;

import java.security.PrivateKey;

public class PrivateKeyWrapper {
    protected final PrivateKey privateKey;

    public PrivateKeyWrapper(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String getDigestOid() {
        String privateKeyAlgorithm = privateKey.getAlgorithm();

        if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_256_NAME) ||
                privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_256_NAME)) {
            return JCSP.GOST_DIGEST_2012_256_OID;
        } else if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_512_NAME) ||
                privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_512_NAME)) {
            return JCSP.GOST_DIGEST_2012_512_OID;
        }
        return JCSP.GOST_DIGEST_OID;
    }

    public String getPublicKeyOid() {
        String privateKeyAlgorithm = privateKey.getAlgorithm();

        if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_256_NAME) ||
                privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_256_NAME)) {
            return JCSP.GOST_PARAMS_SIG_2012_256_KEY_OID;
        } else if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_512_NAME) ||
                privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_512_NAME)) {
            return JCSP.GOST_PARAMS_SIG_2012_512_KEY_OID;
        }
        return JCSP.GOST_EL_KEY_OID;
    }

    public String getSignatureOid() {
        String privateKeyAlgorithm = privateKey.getAlgorithm();

        if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_256_NAME) ||
                privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_256_NAME)) {
            return JCSP.GOST_SIGN_2012_256_OID;
        } else if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_512_NAME) ||
                privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_512_NAME)) {
            return JCSP.GOST_SIGN_2012_512_OID;
        }
        return JCSP.GOST_EL_SIGN_OID;
    }

}
