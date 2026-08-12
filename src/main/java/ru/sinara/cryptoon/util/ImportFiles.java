package ru.sinara.cryptoon.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCP.params.JCPProtectionParameter;
import ru.CryptoPro.JCP.tools.AlgorithmTools;
import ru.CryptoPro.JCP.tools.Encoder;
import ru.CryptoPro.JCSP.JCSP;
import ru.sinara.cryptoon.exception.KeyStoreFailedException;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.stream.Collectors;


public class ImportFiles {
    public static final int FLAG_OPEN_KEY   = 0x0010; // open using getKey
    public static final int FLAG_OPEN_ENTRY = 0x0020; // open using getEntry

    private static final byte[] SIGN_DATA = "security".getBytes(); // signed data
    private static final Logger log = LoggerFactory.getLogger(ImportFiles.class);

    public static void importKeyFromJksFile(String fileName, char[] jksPwd, String alias, char[] hdPwd) {
        KeyStore jksKeyStore;
        KeyStore hdKeyStore;

        log.info("Importing JKS store...");
        
        try (FileInputStream is = new FileInputStream(fileName)) {
            jksKeyStore = KeyStore.getInstance("JKS");
            jksKeyStore.load(is, jksPwd);
        } catch (KeyStoreException | NoSuchAlgorithmException | IOException | CertificateException e) {
            throw new KeyStoreFailedException("JKS Store import failed", e);
        }

        KeyStore.ProtectionParameter jksParameter = new KeyStore.PasswordProtection(jksPwd);
        KeyStore.PrivateKeyEntry jksEntry;
        try {
            jksEntry = (KeyStore.PrivateKeyEntry) jksKeyStore.getEntry(fileName, jksParameter);

            PrivateKey privateKey = jksEntry.getPrivateKey();
            Certificate[] certificates = jksEntry.getCertificateChain();

            log.info("JKS private key: {}", privateKey);
            log.info("JKS certificates: {}\n\t",
                    Arrays.stream(certificates)
                            .map(item -> ((X509Certificate) item).getSubjectX500Principal().toString())
                            .collect(Collectors.joining("\n\t")));

            log.info("Import completed. Saving to the disk...");
            hdKeyStore = KeyStore.getInstance(JCSP.HD_STORE_NAME, JCSP.PROVIDER_NAME);

            log.info("Reading...");
            hdKeyStore.load(null, null);
            log.info("Deleting {}", alias);
            hdKeyStore.deleteEntry(alias); // deleting previous key if exists, for test only

            log.info("Saving...");
            JCPProtectionParameter hdParameter = new JCPProtectionParameter(hdPwd);

            hdKeyStore.setEntry(alias, jksEntry, hdParameter);
            log.info("Saving completed. Trying to check...");

            JCPPrivateKeyEntry hdEntry = (JCPPrivateKeyEntry) hdKeyStore.getEntry(alias, hdParameter);

            privateKey = hdEntry.getPrivateKey();
            certificates = hdEntry.getCertificateChain();

            log.info("%% HD private key: " + privateKey);
            log.info("JKS certificates: {}\n\t",
                    Arrays.stream(certificates)
                            .map(item -> ((X509Certificate) item).getSubjectX500Principal().toString())
                            .collect(Collectors.joining("\n\t")));

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        log.info("Check completed.");
    }

    public static void importKeyFromPfxFile(String fileName, char[] pfxPwd, String alias, char[] hdPwd) {
        KeyStore pfxKeyStore;

        try {
            pfxKeyStore = KeyStore.getInstance(JCSP.PFX_STORE_NAME, JCSP.PROVIDER_NAME);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        try (FileInputStream is = new FileInputStream(fileName)) {
            pfxKeyStore.load(is, pfxPwd);
            log.info("PFX opened");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        try {
            checkStore(
                    pfxKeyStore,
                    FLAG_OPEN_KEY | FLAG_OPEN_ENTRY, // PFX does not need a password for key or entry, so we use both methods
                    JCSP.PROVIDER_NAME,
                    JCSP.HD_STORE_NAME, // export first found key to the disk
                    alias,
                    hdPwd
            );

            printInfo((PrivateKey)pfxKeyStore.getKey(alias, hdPwd),
                    (X509Certificate)pfxKeyStore.getCertificate(alias));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        log.info("Import completed.");

    }

    private static void printInfo(PrivateKey privateKey,
                           X509Certificate certificate) {

        log.info("Private key: {}", privateKey);
        if (certificate != null) {
            var sn = certificate.getSerialNumber().toString(16);
            var subject = getCertificateSubject(certificate).toString();
            var issuer = getCertificateIssuer(certificate).toString();
            log.info("""
                            Certificate:
                            \tSn: {}
                            \tSubject: {}
                            \tIssuer: {}
                            """,
                    sn, subject, issuer);
        }
    }

    /**
     * Check a key store: reading, signing, verifying, saving
     * to another key container.
     * System store can disable some options.
     *
     * @param keyStore Loaded key store.
     * and verifying).
     * @param openFlags Flags that say how to read key.
     * @param provider Provider name.
     * @param exportStoreType Store type for exporting key (the
     * first found).
     * @param exportAlias Alias of exporting key.
     * @param exportPassword Password for exporting key.
     * @throws Exception
     */
    public static void checkStore(
            KeyStore keyStore,
            int openFlags,
            String provider,
            String exportStoreType,
            String exportAlias,
            char[] exportPassword
    ) throws Exception {
        boolean signingCheck = false;

        log.info("Starting check of the store...");
        Enumeration<String> aliases = keyStore.aliases();

        log.info("Items have been found...");
        boolean firstItemForExport = true;

        while (aliases.hasMoreElements()) {

            String alias = aliases.nextElement();
            log.info("ALIAS: {}", alias);

            boolean isKeyEntry = keyStore.isKeyEntry(alias);
            log.info("Is key entry: {}", isKeyEntry);

            boolean isCertificateEntry = keyStore.isCertificateEntry(alias);
            log.info("Is certificate entry: {}", isCertificateEntry);

            PrivateKey privateKey = null;
            Certificate[] chain = null;

            if (isKeyEntry) { // certificate & key
                // Variant 1.
                if ((openFlags & FLAG_OPEN_KEY) != 0) { // use key from getKey
                    // Password may be asked later on signing.
                    privateKey = (PrivateKey) keyStore.getKey(alias, null); // without password if PFX
                    log.info("Private key: {}", privateKey);

                } // if
                else {
                    log.info("Reading of key is disabled.");
                } // else

                Certificate certificate = keyStore.getCertificate(alias);
                byte[] signature = null;

                if (signingCheck && ((openFlags & FLAG_OPEN_KEY) != 0)) { // if check is required and key has been read
                    log.info("Key has been read.");
                    signature = testSign(privateKey, provider);
                } // if
                else {
                    log.info("Signing check is disabled or key has not been read.");
                } // else

                if (certificate != null) {
                    log.info("Certificate: {}", getCertificateSubject(certificate));

                    chain = new Certificate[1];
                    chain[0] = certificate;
//                    if (signingCheck && (signature != null)) { // if check is required and signature has been created
//                        testVerify(certificate.getPublicKey(), provider, signature);
//                    } // if
                } // if

                chain = keyStore.getCertificateChain(alias);
                // Variant 2.
                if ((openFlags & FLAG_OPEN_ENTRY) != 0) { // use key from getEntry

                    // Password is required immediately.

                    JCPProtectionParameter parameter = new JCPProtectionParameter(null, true, true); // without password if PFX
                    JCPPrivateKeyEntry entry = (JCPPrivateKeyEntry) keyStore.getEntry(alias, parameter);

                    privateKey = entry.getPrivateKey();
                    chain = entry.getCertificateChain();

                } // if
                else {
                    log.info("Reading of entry is disabled.");
                } // else

                if (signingCheck && ((openFlags & FLAG_OPEN_ENTRY) != 0)) { // if check is required and entry has been read
                    signature = testSign(privateKey, provider);
                } // if
                else {
                    log.info("Signing check is disabled or entry has not been read.");
                } // else

                if (chain != null && chain.length > 0) {

                    log.info("Certificate[0] from chain: {}", ((X509Certificate) chain[0]).getSubjectX500Principal());

//                    if (signingCheck && (signature != null)) { // if check is required and signature has been created
//                        testVerify(chain[0].getPublicKey(), provider, signature);
//                    } // if
                } // if
            } // if

            if (isCertificateEntry) { // certificate only
                // Variant 1.
                Certificate certificate = keyStore.getCertificate(alias);

                if (certificate != null) {
                    log.info("Certificate only: {}", getCertificateSubject(certificate));
                } // if
                // Variant 2.
                KeyStore.TrustedCertificateEntry entry = (KeyStore.TrustedCertificateEntry) keyStore.getEntry(alias, null);

                if (entry != null && entry.getTrustedCertificate() != null) {
                    log.info("Trusted certificate only: {}", getCertificateSubject(entry.getTrustedCertificate()));
                } // if

                // Variant 3.

                chain = keyStore.getCertificateChain(alias);

                if (chain != null && chain.length > 0) {
                    log.info("Certificate[0] only from chain: {}", getCertificateSubject(chain[0]));
                } // if

            } // if

            // Take an item and export its key and certificates
            // to the HDIMAGE storage.

            if (firstItemForExport && isKeyEntry && exportStoreType != null &&
                    privateKey != null && chain != null && chain.length > 0) {

                KeyStore exportKeyStore = KeyStore.getInstance(exportStoreType, provider);
                exportKeyStore.load(null, null);

                try {
                    log.info("Deleting: {}", exportAlias);
                    exportKeyStore.deleteEntry(exportAlias); // deleting previous key if exists, for test only
                } catch (Exception e) {
                    log.info("Not found: {}", exportAlias);
                }

                log.info("Saving: {}", exportAlias);

                JCPProtectionParameter parameter = new JCPProtectionParameter(exportPassword);
                JCPPrivateKeyEntry entry = new JCPPrivateKeyEntry(privateKey, chain);

                exportKeyStore.setEntry(exportAlias, entry, parameter);
                firstItemForExport = false; // do not export anymore
            } // if
            else {
                log.info("Ignore export for {}", alias);
            }
        } // while
        log.info("Check completed.");
    }

    /**
     * Signing with a private key.
     *
     * The function may:
     * * work successfully if the key does not have a password;
     * * ask the password using CSP dialog and work successfully if entered password is valid, or fail otherwise;
     * * cause errors if the key is unavailable or has invalid state (access denied etc.).
     *
     * @param privateKey Private key.
     * @param provider Provider name.
     * @return binary signature.
     * @throws Exception
     */
    public static byte[] testSign(PrivateKey privateKey,
                                  String provider) throws Exception {

        String sigAlgorithm = AlgorithmTools.getSignatureAlgorithmByPrivateKey(privateKey);
        log.info("\tSigning with algorithm " + sigAlgorithm + "...");

        Signature signature = Signature.getInstance(sigAlgorithm, provider);

        signature.initSign(privateKey);
        signature.update(SIGN_DATA);

        byte[] sign = signature.sign();
        log.info("\tSignature: " + (new Encoder()).encode(sign));

        return sign;

    }

    public static Principal getCertificateSubject(Certificate certificate) {
        return ((X509Certificate) certificate).getSubjectX500Principal();
    }

    public static Principal getCertificateIssuer(Certificate certificate) {
        return ((X509Certificate) certificate).getIssuerX500Principal();
    }

}
