package ru.sinara.cryptoon.jcsp.sign;

import com.objsys.asn1j.runtime.*;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Attribute;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.CertificateSerialNumber;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Name;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Time;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCP.params.JCPProtectionParameter;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCSP.JCSP;
import ru.sinara.cryptoon.core.SignConfiguration;
import ru.sinara.cryptoon.exception.CryptoOperationException;
import ru.sinara.cryptoon.exception.NotSupportedException;
import ru.sinara.cryptoon.jcsp.PrivateKeyWrapper;
import ru.sinara.cryptoon.util.CMStools;

import java.io.IOException;
import java.security.*;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.util.*;

import static ru.sinara.cryptoon.util.CMStools.*;
import static ru.sinara.cryptoon.util.SignTools.*;

public class JcspSignPkcsImpl implements DigitalSignature {

    private final KeyStore keyStore;
    private final String alias;

    private final JCPPrivateKeyEntry privateKeyEntry;

    public JcspSignPkcsImpl(KeyStore keyStore, String alias, char[] password)
            throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableEntryException, KeyStoreException, InvalidKeyException {

        this.keyStore = keyStore;
        this.alias = alias;

        JCPProtectionParameter protectedPassword = new JCPProtectionParameter(password);
        this.privateKeyEntry = (JCPPrivateKeyEntry) keyStore.getEntry(alias, protectedPassword);
    }


    @Override
    public byte[] sign(byte[] data) {
        var wrapper = new PrivateKeyWrapper(privateKeyEntry.getPrivateKey());
        Asn1ObjectIdentifier contentType = new Asn1ObjectIdentifier(new OID(STR_CMS_OID_DATA).value);
        Asn1OctetString digest = new Asn1OctetString(calcDigest(data, wrapper.getDigestOid(), JCSP.PROVIDER_NAME));
        Asn1Type currentTime = getCurrentTime().getElement();


        Map<String, Object> signedAttrs = new TreeMap<>();
        signedAttrs.put(STR_CMS_OID_CONT_TYP_ATTR, contentType);
        signedAttrs.put(STR_CMS_OID_SIGN_TYM_ATTR, currentTime);
        signedAttrs.put(STR_CMS_OID_DIGEST_ATTR, digest);

        SignConfiguration config = SignConfiguration.builder()
                .privateKey(privateKeyEntry.getPrivateKey())
                .certificate(privateKeyEntry.getCertificate())
                .chain(privateKeyEntry.getCertificateChain())
                .signedAttributes(signedAttrs)
                .data(data)
                .detached(true)
                .build();

        try {
            return signPkcs(config);
        } catch (CertificateEncodingException | SignatureException | InvalidKeyException | NoSuchAlgorithmException |
                 NoSuchProviderException | IOException | Asn1Exception e) {
            throw new CryptoOperationException("Sign PKCS7 failed", e);
        }
    }


    private byte[] signPkcs(SignConfiguration config) throws CertificateEncodingException, Asn1Exception, IOException,  NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        boolean detached = config.isDetached();
        X509Certificate cert = config.getCertificate();
        PrivateKey privateKey = config.getPrivateKey();
        byte[] rawData = config.getData();

        PrivateKeyWrapper pkw = new PrivateKeyWrapper(privateKey);
        String digestOid = pkw.getDigestOid();
        String signatureOid = pkw.getSignatureOid();

        final ContentInfo context = new ContentInfo();
        context.contentType = new Asn1ObjectIdentifier(new OID(CMStools.STR_CMS_OID_SIGNED).value);

        final SignedData signedData = new SignedData();
        context.content = signedData;

        signedData.version = new CMSVersion(1);
        // Идентификатор алгоритма хеширования (digest)
        signedData.digestAlgorithms = new DigestAlgorithmIdentifiers(1);

        final DigestAlgorithmIdentifier daiElement = new DigestAlgorithmIdentifier(new OID(digestOid).value);
        daiElement.parameters = new Asn1Null();
        signedData.digestAlgorithms.elements[0] = daiElement;

        Asn1OctetString attachedData = detached ? null : new Asn1OctetString(rawData);
        signedData.encapContentInfo = new EncapsulatedContentInfo(
                new Asn1ObjectIdentifier(new OID(STR_CMS_OID_DATA).value),
                attachedData);

        signedData.certificates = new CertificateSet(1);
        var asnCertificate = new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();
        final Asn1BerDecodeBuffer decodeBuffer = new Asn1BerDecodeBuffer(cert.getEncoded());
        asnCertificate.decode(decodeBuffer);
        signedData.certificates.elements = new CertificateChoices[1];
        signedData.certificates.elements[0] = new CertificateChoices();
        signedData.certificates.elements[0].set_certificate(asnCertificate);


        // Добавляем информацию о подписанте
        SignerInfo signerInfo = new SignerInfo();
        signerInfo.version = new CMSVersion(1);
        signerInfo.sid = new SignerIdentifier();

        SignerInfos signerInfos = new SignerInfos(1);
        signerInfos.elements[0] = signerInfo;
        signedData.signerInfos = signerInfos;

        byte[] encodedName = cert.getIssuerX500Principal().getEncoded();
        final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
        final Name name = new Name();
        name.decode(nameBuf);
        final CertificateSerialNumber num = new CertificateSerialNumber(cert.getSerialNumber());

        signerInfo.sid.set_issuerAndSerialNumber(new IssuerAndSerialNumber(name, num));
        signerInfo.digestAlgorithm = new DigestAlgorithmIdentifier(new OID(digestOid).value);
        signerInfo.digestAlgorithm.parameters = new Asn1Null();
        signerInfo.signatureAlgorithm = new SignatureAlgorithmIdentifier(new OID(signatureOid).value);
        signerInfo.signatureAlgorithm.parameters = new Asn1Null();
        var rawSignature = signRaw(privateKey, rawData);
        signerInfo.signature = new SignatureValue(rawSignature);

        SignedAttributes signedAttrs = new SignedAttributes(config.getSignedAttributes());
        signerInfo.signedAttrs = signedAttrs;

        Asn1BerEncodeBuffer encBufSignedAttr = new Asn1BerEncodeBuffer();
        signedAttrs.encode(encBufSignedAttr);

        final Signature signature = Signature.getInstance(JCP.GOST_SIGN_2012_256_OID, JCSP.PROVIDER_NAME);
        final byte[] hSign = encBufSignedAttr.getMsgCopy();
        signature.initSign(privateKey);
        signature.update(hSign);
        byte[] sign = signature.sign();

        signerInfo.signature = new SignatureValue(sign);

        // Получаем закодированную подпись
        final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
        context.encode(asnBuf, true);
        return asnBuf.getMsgCopy();
    }


    private byte[] signRaw(PrivateKey privateKey, byte[] rawData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String signAlgorithm = switch (privateKey.getAlgorithm()) {
            case JCP.GOST_EL_2012_256_NAME, JCP.GOST_DH_2012_256_NAME -> JCP.GOST_SIGN_2012_256_NAME;
            case JCP.GOST_EL_2012_512_NAME, JCP.GOST_DH_2012_512_NAME -> JCP.GOST_SIGN_2012_512_NAME;
            default -> null;
        };
        Objects.requireNonNull(signAlgorithm, () -> {
            throw new NotSupportedException("Private Key Algorithm " + privateKey.getAlgorithm() + " not supported");
        });
        final Signature signature = java.security.Signature.getInstance(signAlgorithm);
        signature.initSign(privateKey);
        signature.update(rawData);
        return signature.sign();
    }



}
