package ru.sinara.cryptoon.core;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Set;

interface ISignConfiguration {
    PrivateKey getPrivateKey();
    X509Certificate getCertificate();
    List<X509Certificate> getChain();
    Collection<X509CertificateHolder> getChainHolder();
    Set<X509CRL> getCRLs();
    Collection<X509CRLHolder> getCRLsHolder();
    AttributeTable getSignedAttributes() throws Exception;
    AttributeTable getUnsignedAttributes() throws Exception;
    CollectionStore<X509Certificate> getCertificateStore();
    CollectionStore<X509CRL> getCRLStore();
    InputStream getDataStream() throws Exception;
    String getTSAAddress();
    boolean isDetached();
    String getProviderName();
    String getDigestOid();
    String getPublicKeyOid();
    String getSignatureOid();
}
