package ru.sinara.cryptoon.jcsp.sign;

import org.bouncycastle.util.CollectionStore;
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCSP.JCSP;
import ru.sinara.cryptoon.config.Configuration;
import ru.sinara.cryptoon.config.SimpleConfiguration;
import ru.sinara.cryptoon.config.container.ISignatureContainer;
import ru.sinara.cryptoon.core.SignAlgorithm;
import ru.sinara.cryptoon.exception.CryptoOperationException;

import java.security.*;

import static ru.sinara.cryptoon.util.SignTools.createMixedSignatureWith2Signers;

public class JcspSignatureImpl implements DigitalSignature {

    private final Signature signer;

    public JcspSignatureImpl(SignAlgorithm signAlgorithm, KeyStore keyStore, String alias, KeyStore.ProtectionParameter protectedPassword)
            throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableEntryException, KeyStoreException, InvalidKeyException {
        this.signer = Signature.getInstance(signAlgorithm.getValue(), JCSP.PROVIDER_NAME);
        JCPPrivateKeyEntry privateKeyEntry = (JCPPrivateKeyEntry) keyStore.getEntry(alias, protectedPassword);
        signer.initSign(privateKeyEntry.getPrivateKey());
    }

    @Override
    public byte[] sign(byte[] data) {
        try {
            signer.update(data);
            return signer.sign();
        } catch (SignatureException e) {
            throw new CryptoOperationException("", e);
        }
    }

    public byte[] signCades(ISignatureContainer container, boolean useStream) {

        try {

            var configDetached = new SimpleConfiguration(container, true, useStream);

            // Подпись без дополнительных пользовательских аттрибутов.
//            createMixedSignatureWith2Signers(configAttached,
//                    SimpleConfiguration.getTempFileName(null));

            // Подпись с дополнительными пользовательскими подписываемыми
            // аттрибутами.
//            configDetached.setSignedAttributes(Configuration.getSomeSignedAttributes(true, true));
//            createMixedSignatureWith2Signers(configDetached,
//                    SimpleConfiguration.getTempFileName("signedAttrs_det_"));

            // Подпись с дополнительными пользовательскими неподписываемыми
            // аттрибутами, а также сертификатами, вложенными в SignedData.
//            configAttached.setUnsignedAttributes(Configuration.getSomeUnsignedAttributes(true));
//            configAttached.setCertificateStore(new CollectionStore(configAttached.getChainHolder()));
//            createMixedSignatureWith2Signers(configAttached,
//                    SimpleConfiguration.getTempFileName("unsignedAttrs_certs_"));

            // Подпись с дополнительными пользовательскими подписываемыми
            // и неподписываемыми аттрибутами, а также сертификатами м СОС,
            // вложенными в SignedData.
            configDetached.setSignedAttributes(Configuration.getSomeUnsignedAttributes(true));
            configDetached.setCertificateStore(new CollectionStore(configDetached.getChainHolder()));
            configDetached.setCRLStore(new CollectionStore(configDetached.getCRLsHolder()));

            createMixedSignatureWith2Signers(configDetached,
                    SimpleConfiguration.getTempFileName("allAttrs_det_certs_crls_"));

        } catch (Exception e) {
            Configuration.printCAdESException(e);
        }
    }
}
