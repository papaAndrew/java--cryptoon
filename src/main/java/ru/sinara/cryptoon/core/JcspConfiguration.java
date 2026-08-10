package ru.sinara.cryptoon.core;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;
import ru.CryptoPro.JCSP.JCSP;
import ru.sinara.cryptoon.config.container.ISignatureContainer;
import ru.sinara.cryptoon.exception.EntryUnavailableException;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

import static ru.sinara.cryptoon.config.Configuration.TSA_DEFAULT_ADDRESS;

public class JcspConfiguration implements ISignConfiguration {
    /**
     * Контейнер подписи.
     */
    protected final ISignatureContainer signatureContainer;

    protected boolean detached;
    protected PrivateKey privateKey;
    protected AttributeTable signedAttributes;
    protected AttributeTable unsignedAttributes;

    protected final List<X509Certificate> chain = new ArrayList<>();
    /**
     * Список сертификатов для добавления в подпись.
     */
    protected final List<X509Certificate> additionalCerts = new ArrayList<>();
    /**
     * Список СОС для проверки подписи.
     */
    protected final Set<X509CRL> crls = new HashSet<>();
    /**
     * Список СОС для добавления в подпись.
     */
    protected final List<X509CRL> additionalCrls = new ArrayList<>();


    public JcspConfiguration(ISignatureContainer signatureContainer) {
        this.signatureContainer = signatureContainer;
    }


    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public X509Certificate getCertificate() {
        return chain.stream().findFirst().orElse(null);
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
    public AttributeTable getSignedAttributes() throws Exception {
        return signedAttributes;
    }

    @Override
    public AttributeTable getUnsignedAttributes() throws Exception {
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
    public InputStream getDataStream() throws Exception {
        return null;        // TODO
    }

    @Override
    public String getTSAAddress() {
        return
                (signatureContainer != null &&
                        signatureContainer.getTsaAddress() != null)
                        ? signatureContainer.getTsaAddress()
                        : TSA_DEFAULT_ADDRESS;

    }

    @Override
    public boolean isDetached() {
        return detached;
    }

    @Override
    public String getProviderName() {
        return JCSP.PROVIDER_NAME;
    }

    @Override
    public String getDigestOid() {
        String privateKeyAlgorithm = privateKey.getAlgorithm();

        if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_256_NAME) ||
                privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_256_NAME)) {
            return JCSP.GOST_DIGEST_2012_256_OID;
        } // if
        else if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_512_NAME) ||
                privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_512_NAME)) {
            return JCSP.GOST_DIGEST_2012_512_OID;
        } // if
        return JCSP.GOST_DIGEST_OID;
    }

    @Override
    public String getPublicKeyOid() {
        String privateKeyAlgorithm = privateKey.getAlgorithm();

        if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_256_NAME) ||
                (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_256_NAME))) {
            return JCSP.GOST_PARAMS_SIG_2012_256_KEY_OID;
        } // if
        else if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_512_NAME) ||
                (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_512_NAME))) {
            return JCSP.GOST_PARAMS_SIG_2012_512_KEY_OID;
        } // else

        return JCSP.GOST_EL_KEY_OID;
    }

    @Override
    public String getSignatureOid() {

        String privateKeyAlgorithm = privateKey.getAlgorithm();

        if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_256_NAME) ||
                privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_256_NAME)) {
            return JCSP.GOST_SIGN_2012_256_OID;
        } // if
        else if (privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_EL_2012_512_NAME) ||
                privateKeyAlgorithm.equalsIgnoreCase(JCSP.GOST_DH_2012_512_NAME)) {
            return JCSP.GOST_SIGN_2012_512_OID;
        } // if

        return JCSP.GOST_EL_SIGN_OID;
    }

}
