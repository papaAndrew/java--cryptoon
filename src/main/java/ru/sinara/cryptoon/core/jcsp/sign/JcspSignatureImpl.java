package ru.sinara.cryptoon.core.jcsp.sign;

import ru.CryptoPro.JCSP.JCSP;
import ru.sinara.cryptoon.core.KeyProvider;
import ru.sinara.cryptoon.core.jcsp.SignAlgorithm;

import java.security.*;

public class JcspSignatureImpl implements DigitalSignature {

    private final Signature signer;
    private final KeyProvider keyProvider;

    public JcspSignatureImpl(SignAlgorithm signAlgorithm, KeyProvider keyProvider) throws NoSuchAlgorithmException, NoSuchProviderException {
        this.signer = Signature.getInstance(signAlgorithm.getValue(), JCSP.PROVIDER_NAME);
        this.keyProvider = keyProvider;
    }

    @Override
    public byte[] sign(byte[] data) throws InvalidKeyException, SignatureException {
        PrivateKey privateKey = keyProvider.getPrivateKey();

        signer.initSign(privateKey);
        signer.update(data);

        return signer.sign();
    }
}
