package ru.sinara.cryptoon.util;

import com.objsys.asn1j.runtime.*;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Time;
import ru.CryptoPro.JCP.params.OID;
import ru.sinara.cryptoon.exception.CryptoOperationException;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;

import static ru.sinara.cryptoon.util.CMStools.STR_CMS_OID_DATA;

public class SignTools {

    public static void cadesSignatureUpdate(CAdESSignature cAdESSignature, InputStream dataStream) throws Exception {

        final int buffer_size = 1024 * 1024;
        byte[] buffer = new byte[buffer_size];
        int read;

        while ((read = dataStream.read(buffer, 0, buffer_size)) > 0) {
            cAdESSignature.update(buffer, 0, read);
        }

    }


    public static byte[] calcDigest(byte[] bytes, String digestAlgorithmName, String providerName) {
        //calculation messageDigest
        try (ByteArrayInputStream stream = new ByteArrayInputStream(bytes)) {
            final MessageDigest digest = MessageDigest.getInstance(digestAlgorithmName, providerName);
            final DigestInputStream digestStream = new DigestInputStream(stream, digest);
            while (digestStream.available() != 0) {
                digestStream.read();
            };
            return digest.digest();
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new CryptoOperationException("Calculate digest failure", e);
        }

    }


    public static List<X509Certificate> mapX509Chain(Certificate[] chain) {
        return Arrays.stream(chain)
                .filter(c -> c instanceof X509Certificate)
                .map(c -> (X509Certificate) c)
                .collect(Collectors.toList());
    }

    public static Time getCurrentTime() {
        final Time time = new Time();
        final Asn1UTCTime UTCTime = new Asn1UTCTime();
        Calendar calendar = Calendar.getInstance();
        try {
            UTCTime.setTime(calendar);
        } catch (Asn1Exception e) {
            throw new CryptoOperationException("Get ASN1 UTC Time failed", e);
        }
        time.set_utcTime(UTCTime);
        return time;
    }



}
