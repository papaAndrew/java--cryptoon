package ru.sinara.cryptoon.core;

import org.bouncycastle.util.CollectionStore;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Attribute;

import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

public class JcspConfiguration implements SignConfiguration {

//    protected final ISignatureContainer signatureContainer;

    protected boolean detached;
    protected PrivateKey privateKey;
    protected X509Certificate certificate;
    protected Attribute[] signedAttributes;
    protected Attribute[] unsignedAttributes;
    protected Integer cadesType;
    protected byte[] data;

    protected final List<X509Certificate> chain = new ArrayList<>();
    protected final List<X509Certificate> additionalCerts = new ArrayList<>();
    protected final Set<X509CRL> crls = new HashSet<>();
    protected final List<X509CRL> additionalCrls = new ArrayList<>();

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public X509Certificate getCertificate() {
        return certificate;
    }

    @Override
    public List<X509Certificate> getChain() {
        return chain;
    }


    @Override
    public Set<X509CRL> getCRLs() {
        return crls;
    }


    @Override
    public Attribute[] getSignedAttributes() {
        return signedAttributes;
    }

    @Override
    public Attribute[] getUnsignedAttributes() {
        return unsignedAttributes;
    }

    @Override
    public CollectionStore<X509Certificate> getCertificateStore() {
        return new CollectionStore<>(additionalCerts);
    }

    @Override
    public CollectionStore<X509CRL> getCRLStore() {
        return new CollectionStore<>(additionalCrls);
    }

    @Override
    public byte[] getData() {
        return data;
    }


    @Override
    public boolean isDetached() {
        return detached;
    }


}
