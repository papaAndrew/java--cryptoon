package ru.sinara.cryptoon.core;

import com.objsys.asn1j.runtime.Asn1Type;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Attribute;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Attribute_values;
import ru.CryptoPro.JCP.params.OID;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

public interface SignConfiguration {
    PrivateKey getPrivateKey();
    X509Certificate getCertificate();
    List<X509Certificate> getChain();
    Set<X509CRL> getCRLs();
    Attribute[] getSignedAttributes();
    Attribute[] getUnsignedAttributes();
    CollectionStore<X509Certificate> getCertificateStore();
    CollectionStore<X509CRL> getCRLStore();
    byte[] getData();
    boolean isDetached();

    public static Attribute getSingleAsn1Attribute(String key, Asn1Type value) {
        var ident = new OID(key).value;
        var values = new Attribute_values(1);
        values.elements[0] = value;
        return new Attribute(ident, values);
    }

    public static Attribute getSingleAsn1Attribute(Map.Entry<String, Asn1Type> entry) {
        return getSingleAsn1Attribute(entry.getKey(), entry.getValue()) ;
    }


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

        public JcspConfigurationBuilder signedAttributes(Map<String, Asn1Type> attributes) {
            configuration.signedAttributes = attributes.entrySet().stream()
                    .map(SignConfiguration::getSingleAsn1Attribute)
                    .toArray(Attribute[]::new);
            return this;
        }

        public JcspConfigurationBuilder unsignedAttributes(Map<String, Asn1Type> attributes) {
            configuration.unsignedAttributes = attributes.entrySet().stream()
                    .map(SignConfiguration::getSingleAsn1Attribute)
                    .toArray(Attribute[]::new);
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
