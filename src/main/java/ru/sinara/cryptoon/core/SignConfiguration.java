package ru.sinara.cryptoon.core;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Attribute;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

public interface SignConfiguration {
    PrivateKey getPrivateKey();
    X509Certificate getCertificate();
    List<X509Certificate> getChain();
    Collection<X509CertificateHolder> getChainHolder();
    Set<X509CRL> getCRLs();
    Collection<X509CRLHolder> getCRLsHolder();
    Attribute[] getSignedAttributes();
    Attribute[] getUnsignedAttributes();
    CollectionStore<X509Certificate> getCertificateStore();
    CollectionStore<X509CRL> getCRLStore();
    byte[] getData();
    boolean isDetached();

    static JcspConfigurationBuilder builder() {
        return new JcspConfigurationBuilder();
    }


    class JcspConfigurationBuilder {

        private final JcspConfiguration configuration;

        private JcspConfigurationBuilder() {
            this.configuration = new JcspConfiguration();
        }

        public JcspConfigurationBuilder detached(boolean detached) {
            configuration.detached = detached;
            return this;
        }

        public JcspConfigurationBuilder privateKey(PrivateKey privateKey) {
            configuration.privateKey = privateKey;
            return this;
        }

        public JcspConfigurationBuilder signedAttributes(List<Attribute> signedAttributes) {
            configuration.signedAttributes.addAll(signedAttributes);
            return this;
        }

        public JcspConfigurationBuilder unsignedAttributes(List<Attribute> unsignedAttributes) {
            configuration.unsignedAttributes.addAll(unsignedAttributes);
            return this;
        }

        public JcspConfigurationBuilder chain(Certificate[] certificates) {
            var chain = Arrays.stream(certificates)
                    .map(item -> (X509Certificate) item)
                    .toList();
            configuration.chain.addAll(chain);
            return this;
        }

        public JcspConfigurationBuilder additionalCerts(List<X509Certificate> additionalCerts) {
            configuration.additionalCerts.addAll(additionalCerts);
            return this;
        }

        public JcspConfigurationBuilder crls(Set<X509CRL> crls) {
            configuration.crls.addAll(crls);
            return this;
        }

        public JcspConfigurationBuilder additionalCrls(List<X509CRL> additionalCrls) {
            configuration.additionalCrls.addAll(additionalCrls);
            return this;
        }

        public JcspConfigurationBuilder cadesType(Integer cadesType) {
            configuration.cadesType = cadesType;
            return this;
        }

        public JcspConfigurationBuilder data(byte[] data) {
            configuration.data = data;
            return this;
        }

        public JcspConfigurationBuilder certificate(Certificate certificate) {
            configuration.certificate = (X509Certificate) certificate;
            return this;
        }

        public SignConfiguration build() {
            return configuration;
        }
    }

}
