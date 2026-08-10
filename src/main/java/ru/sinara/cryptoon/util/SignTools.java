package ru.sinara.cryptoon.util;

import org.bouncycastle.asn1.cms.AttributeTable;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCP.tools.Array;
import ru.sinara.cryptoon.config.IConfiguration;

import java.io.*;

public class SignTools {

    /**
     * Хеширование потока данных.
     *
     * @param cAdESSignature Объект класса CAdESSignature.
     * @param dataStream Поток данных.
     * @throws Exception
     */
    public static void cadesSignatureUpdate(CAdESSignature cAdESSignature, InputStream dataStream) throws Exception {

        final int buffer_size = 1024*1024;
        byte[] buffer = new byte[buffer_size];
        int read;

        while ( (read = dataStream.read(buffer, 0, buffer_size)) > 0 ) {
            cAdESSignature.update(buffer, 0, read);
        } // while

    }

    /**
     * Создание CAdES-подписи с двумя подписантами: CAdES-BES и
     * CAdES-X Long Type 1.
     *
     * @param config Конфигурация подписи.
     * @param outFileName Файл для сохранения подписи.
     * @throws Exception
     */
    public static void createMixedSignatureWith2Signers(IConfiguration config, String outFileName) throws Exception {
        InputStream signatureStream = createMixedSignatureWith2SignersAsStream(config, outFileName);
        signatureStream.close();
    }


    /**
     * Создание CAdES-подписи с двумя подписантами: CAdES-BES и
     * CAdES-X Long Type 1.
     *
     * @param config Конфигурация подписи.
     * @param outFileName Файл для сохранения подписи.
     * @return подпись.
     * @throws Exception
     */
    public static InputStream createMixedSignatureWith2SignersAsStream(
            IConfiguration config,
            String outFileName
    ) throws Exception {

        CAdESSignature cadesSignature = new CAdESSignature(config.detached());

        cadesSignature.setCertificateStore(config.getCertificateStore());
        cadesSignature.setCRLStore(config.getCRLStore());

        // Создаем подписанта CAdES-BES.
        cadesSignature.addSigner(config.getProviderName(),
                config.getDigestOid(),
                config.getPublicKeyOid(),
                config.getPrivateKey(),
                config.getChain(),
                CAdESType.CAdES_BES,
                null,
                false,
                config.getSignedAttributes(),
                config.getUnsignedAttributes(),
                config.getCRLs());

//        // Создаем подписанта CAdES-X Long Type 1.
//        cadesSignature.addSigner(config.getProviderName(),
//                config.getDigestOid(),
//                config.getPublicKeyOid(),
//                config.getPrivateKey(),
//                config.getChain(),
//                CAdESType.CAdES_X_Long_Type_1,
//                config.getTSAAddress(),
//                false,
//                null,
//                null,
//                config.getCRLs());

        // Сохраним подпись либо в файл, либо в массив.
        OutputStream outSignatureStream = config.useStream()
                ? new FileOutputStream(outFileName) : new ByteArrayOutputStream();

        cadesSignature.open(outSignatureStream);
        InputStream dataStream = config.getDataStream();
        cadesSignatureUpdate(cadesSignature, dataStream); // хеш

        // Завершаем создание подписи с двумя подписантами.
        cadesSignature.close();
        dataStream.close();
        outSignatureStream.close();

        CAdESSigner[] signers = cadesSignature.getCAdESSignerInfos();
        for (int i = 0; i < signers.length; i++) {

            CAdESSigner signer = signers[i];

            // Только ему могут подаваться атрибуты (см. выше).
            if (signer.getSignatureType().equals(CAdESType.CAdES_BES)) {

                AttributeTable cdsAttrs = signer.getSignerSignedAttributes();
                if (config.getSignedAttributes() != null) {
                    if (config.getSignedAttributes().size() != cdsAttrs.size()) {
                        throw new Exception("Invalid count of signed attributes in " +
                                "CAdES signature # " + i);
                    } // if
                } // if
                else {
                    if (cdsAttrs != null) {
                        throw new Exception("Count of signed attributes must be null " +
                                "in CAdES signature # " + i);
                    } // if
                } // else

                cdsAttrs = signer.getSignerUnsignedAttributes();
                if (config.getUnsignedAttributes() != null) {
                    if (config.getUnsignedAttributes().size() != cdsAttrs.size()) {
                        throw new Exception("Invalid count of unsigned attributes in " +
                                "CAdES signature # " + i);
                    } // if
                } // if
                else {
                    if (cdsAttrs != null) {
                        throw new Exception("Count of unsigned attributes must be null " +
                                "in CAdES signature # " + i);
                    } // if
                } // else

            } // if

        } // for

        InputStream signatureStream;

        // Если это массив, сохраним и снова прочтем.
        if (!config.useStream() && outSignatureStream instanceof ByteArrayOutputStream) {

            byte[] cadesCms = ((ByteArrayOutputStream)outSignatureStream).toByteArray();

            if (outFileName != null) {
                Array.writeFile(outFileName, cadesCms);
            } // if

            // Подпись.
            signatureStream = new ByteArrayInputStream(cadesCms);

        } // if
        else {
            // Читаем подпись.
            signatureStream = new FileInputStream(outFileName);
        } // else

        return signatureStream;
    }

}
