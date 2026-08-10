package ru.sinara.cryptoon.jcsp.sign;

import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.exception.CAdESException;
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCSP.JCSP;
import ru.sinara.cryptoon.core.JcspConfiguration;
import ru.sinara.cryptoon.core.SignAlgorithm;
import ru.sinara.cryptoon.exception.CryptoOperationException;

import java.security.*;

import static ru.sinara.cryptoon.util.SignTools.createCadesSignature;
import static ru.sinara.cryptoon.util.SignTools.mapX509Chain;

public class JcspSignCadesImpl implements DigitalSignature {

    private final Signature signer;
    private final JCPPrivateKeyEntry privateKeyEntry;

    public JcspSignCadesImpl(SignAlgorithm signAlgorithm, KeyStore keyStore, String alias, KeyStore.ProtectionParameter protectedPassword)
            throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableEntryException, KeyStoreException, InvalidKeyException {

        this.signer = Signature.getInstance(signAlgorithm.getValue(), JCSP.PROVIDER_NAME);
        this.privateKeyEntry = (JCPPrivateKeyEntry) keyStore.getEntry(alias, protectedPassword);
        signer.initSign(privateKeyEntry.getPrivateKey());
    }

    @Override
    public byte[] signRaw(byte[] data) {
        try {
            signer.update(data);
            return signer.sign();
        } catch (SignatureException e) {
            throw new CryptoOperationException("", e);
        }
    }

    @Override
    public byte[] signCades(byte[] data) {

        try {
            var chain = mapX509Chain(privateKeyEntry.getCertificateChain());
            var configDetached = JcspConfiguration.builder()
                    .detached(true)
                    .cadesType(CAdESType.CAdES_BES)
                    .privateKey(privateKeyEntry.getPrivateKey())
                    .data(data)
                    .chain(chain)
                    .build();

            return createCadesSignature(configDetached);
        } catch (Exception e) {
            if (e instanceof CAdESException) {
                System.out.println(e.getMessage() + " (" + ((CAdESException)e).getErrorCode() + ")");
            } else if (e.getCause() instanceof CAdESException) {
                CAdESException ex = (CAdESException)e.getCause();
                System.out.println(ex.getMessage() + " (" + ex.getErrorCode() + ")");
            } else {
                e.printStackTrace();
            }
            return null;
        }

    }


}
