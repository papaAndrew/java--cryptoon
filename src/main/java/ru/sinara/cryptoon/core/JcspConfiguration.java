package ru.sinara.cryptoon.core;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Attribute;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate;
import ru.CryptoPro.JCSP.JCSP;
import ru.sinara.cryptoon.exception.EntryUnavailableException;

import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

public class JcspConfiguration implements SignConfiguration {

//    protected final ISignatureContainer signatureContainer;

    protected boolean detached;
    protected PrivateKey privateKey;
    protected X509Certificate certificate;
    protected List<Attribute> signedAttributes;
    protected List<Attribute> unsignedAttributes;
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
    public Collection<X509CertificateHolder> getChainHolder() {
        return chain.stream()
                .map(cert -> {
                    try {
                        byte[] encoded = cert.getEncoded();
                        return new X509CertificateHolder(encoded);
                    } catch (Exception e) {
                        throw new EntryUnavailableException("ChainHolder create failed", e);
                    }
                })
                .toList();
    }

    @Override
    public Set<X509CRL> getCRLs() {
        return crls;
    }

    @Override
    public Collection<X509CRLHolder> getCRLsHolder() {
        return crls.stream()
                .map(cert -> {
                    try {
                        return new X509CRLHolder(cert.getEncoded());
                    } catch (Exception e) {
                        throw new EntryUnavailableException("CRLsHolder create failed", e);
                    }
                })
                .toList();
    }

    @Override
    public Attribute[] getSignedAttributes() {
        return signedAttributes.toArray(new Attribute[0]);
    }

    @Override
    public Attribute[] getUnsignedAttributes() {
        return unsignedAttributes.toArray(new Attribute[0]);
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
