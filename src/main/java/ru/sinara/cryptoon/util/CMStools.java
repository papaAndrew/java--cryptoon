package ru.sinara.cryptoon.util;

import com.objsys.asn1j.runtime.Asn1Exception;
import com.objsys.asn1j.runtime.Asn1Type;
import com.objsys.asn1j.runtime.Asn1UTCTime;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Time;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.Array;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.logging.Logger;

/**
 * @author Copyright 2004-2009 Crypto-Pro. All rights reserved.
 * @version 2.5
 */
public class CMStools {

    /**
     * расширение файла сертификата
     */
    public static final String CERT_EXT = ".cer";
    /**
     * расширение файла
     */
    public static final String CMS_EXT = ".p7b";
    /**
     * разделитель
     */
    public static final String SEPAR = File.separator;
    /**
     * рабочая директория
     */
    public static String TEST_PATH = System.getProperty("user.dir") + SEPAR + "temp";

    /**
     * имя отправителя (контейнер, сертификат)
     */

    // ГОСТ Р 34.10-2001
    public static final String SIGN_KEY_NAME = "gost_dup";
    public static final String SIGN_KEY_NAME_CONT = "gostrdup.000";
    public static final char[] SIGN_KEY_PASSWORD = "Pass1234".toCharArray();
    public static String SIGN_CERT_PATH = TEST_PATH + SEPAR + SIGN_KEY_NAME + CERT_EXT;

    // ГОСТ Р 34.10-2012 (256)
    public static final String SIGN_KEY_NAME_2012_256 = "client_key_2012_256";
    public static final String SIGN_KEY_NAME_CONT_2012_256 = "clientrk.000";
    public static final char[] SIGN_KEY_PASSWORD_2012_256 = "pass1".toCharArray();
    public static String SIGN_CERT_PATH_2012_256 = TEST_PATH + SEPAR + SIGN_KEY_NAME_2012_256 + CERT_EXT;

    // ГОСТ Р 34.10-2012 (512)
    public static final String SIGN_KEY_NAME_2012_512 = "client_key_2012_512";
    public static final String SIGN_KEY_NAME_CONT_2012_512 = "clientrk.001";
    public static final char[] SIGN_KEY_PASSWORD_2012_512 = "pass3".toCharArray();
    public static String SIGN_CERT_PATH_2012_512 = TEST_PATH + SEPAR + SIGN_KEY_NAME_2012_512 + CERT_EXT;

    /**
     * имя получателя (контейнер, сертификат)
     */

    // ГОСТ Р 34.10-2001
    public static final String RECIP_KEY_NAME = "afevma_dup";
    public static final String RECIP_KEY_NAME_CONT = "afevmard.000";
    public static final char[] RECIP_KEY_PASSWORD = "security".toCharArray();
    public static String RECIP_CERT_PATH = TEST_PATH + SEPAR + RECIP_KEY_NAME + CERT_EXT;

    // ГОСТ Р 34.10-2012 (256)
    public static final String RECIP_KEY_NAME_2012_256 = "server_key_2012_256";
    public static final String RECIP_KEY_NAME_CONT_2012_256 = "serverrk.000";
    public static final char[] RECIP_KEY_PASSWORD_2012_256 = "pass2".toCharArray();
    public static String RECIP_CERT_PATH_2012_256 = TEST_PATH + SEPAR + RECIP_KEY_NAME_2012_256 + CERT_EXT;

    // ГОСТ Р 34.10-2012 (512)
    public static final String RECIP_KEY_NAME_2012_512 = "server_key_2012_512";
    public static final String RECIP_KEY_NAME_CONT_2012_512 = "serverrk.001";
    public static final char[] RECIP_KEY_PASSWORD_2012_512 = "pass4".toCharArray();
    public static String RECIP_CERT_PATH_2012_512 = TEST_PATH + SEPAR + RECIP_KEY_NAME_2012_512 + CERT_EXT;

    /**
     * алгоритмы и т.д.
     */

    public static final String STORE_TYPE = JCP.HD_STORE_NAME;

    // ГОСТ Р 34.10-2001
    public static final String KEY_ALG_NAME = JCP.GOST_EL_DH_NAME;
    public static final String DIGEST_ALG_NAME = JCP.GOST_DIGEST_NAME;

    // ГОСТ Р 34.10-2012 (256)
    public static final String KEY_ALG_NAME_2012_256 = JCP.GOST_DH_2012_256_NAME;
    public static final String DIGEST_ALG_NAME_2012_256 = JCP.GOST_DIGEST_2012_256_NAME;

    // ГОСТ Р 34.10-2012 (512)
    public static final String KEY_ALG_NAME_2012_512 = JCP.GOST_DH_2012_512_NAME;
    public static final String DIGEST_ALG_NAME_2012_512 = JCP.GOST_DIGEST_2012_512_NAME;

    public static final String SEC_KEY_ALG_NAME = "GOST28147";
    public static final String MAGMA_ALG_NAME = "GOST3412_2015_M";

    /**
     * Идентификатор для передачи параметров экспорта/импорта
     * сессионного ключа (ГОСТ Р 34.10-2012-256).
     */
    public static final String STR_WRAP_GOST_2012_256_ESDH = "1.2.643.7.1.1.6.1";

    /**
     * Идентификатор для передачи параметров экспорта/импорта
     * сессионного ключа (ГОСТ Р 34.10-2012-512).
     */
    public static final String STR_GOST_2012_512_ESDH = "1.2.643.7.1.1.6.2";

    /**
     * Идентификатор алгоритма шифрования ключа ГОСТ3412_2015 Магма.
     */
    public static final String STR_KEY_WRAP_ALG_ID_M = "1.2.643.7.1.1.7.1.1";

    /**
     * Идентификатор атрибута omac.
     */
    public static final String STR_CMS_GR3412_OMAC = "1.2.643.7.1.0.6.1.1";

    /**
     * OIDs для CMS
     */
    public static final String STR_CMS_OID_DATA = "1.2.840.113549.1.7.1";
    public static final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.7.2";
    public static final String STR_CMS_OID_ENVELOPED = "1.2.840.113549.1.7.3";

    public static final String STR_CMS_OID_CONT_TYP_ATTR = "1.2.840.113549.1.9.3";
    public static final String STR_CMS_OID_DIGEST_ATTR = "1.2.840.113549.1.9.4";
    public static final String STR_CMS_OID_SIGN_TYM_ATTR = "1.2.840.113549.1.9.5";

    public static final String STR_CMS_OID_TS = "1.2.840.113549.1.9.16.1.4";

    // ГОСТ Р 34.10-2001
    public static final String DIGEST_OID = JCP.GOST_DIGEST_OID;
    public static final String SIGN_OID = JCP.GOST_EL_KEY_OID;

    // ГОСТ Р 34.10-2012 (256)
    public static final String DIGEST_OID_2012_256 = JCP.GOST_DIGEST_2012_256_OID;
    public static final String SIGN_OID_2012_256 = JCP.GOST_PARAMS_SIG_2012_256_KEY_OID;

    // ГОСТ Р 34.10-2012 (512)
    public static final String DIGEST_OID_2012_512 = JCP.GOST_DIGEST_2012_512_OID;
    public static final String SIGN_OID_2012_512 = JCP.GOST_PARAMS_SIG_2012_512_KEY_OID;


}
