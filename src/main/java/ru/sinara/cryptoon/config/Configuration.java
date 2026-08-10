/**
 * Copyright 2004-2012 Crypto-Pro. All rights reserved.
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package ru.sinara.cryptoon.config;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.CollectionStore;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESSignerXLT1;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.exception.CAdESException;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCP.params.JCPProtectionParameter;
import ru.sinara.cryptoon.config.container.ISignatureContainer;
import ru.sinara.cryptoon.util.ResolveProvider;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Различные константы для конфигураторов, использующихся в
 * примерах.
 * 
 * 17/04/2012
 *
 */
public abstract class Configuration implements IConfiguration {

    /**
     * Тип контейнера JCSP по умолчанию.
     */
    // TODO: добавить проверку if windows then registry else hdimage.
    private static final String JCSP_DEFAULT_STORE_TYPE = ResolveProvider.ALTERNATIVE_HD_IMAGE;
    /**
     * Папка с ресурсами.
     */
     static final String TEST_PATH = System.getProperty("user.dir") +
        File.separator + "data";
    /**
     * Путь к папке для сохранения подписей.
     */
    public static final String TEMP_PATH = System.getProperty("user.dir") +
        File.separator + "temp";
    /**
     * Путь к СОС.
     */
    public static final String CRL_PATH = TEST_PATH +
        File.separator + "CRLS" + File.separator + "GOST2012" +
            File.separator + "root.crl";
    /**
     * Адрес TSA.
     */
    public static final String TSA_DEFAULT_ADDRESS = "http://www.cryptopro.ru:80/tsp/";
	/**
	 * Данные для подписи.
	 */
	public static final byte[] DATA = "Security is only our business.".getBytes();
	/**
	 * Отступ при печати.
	 */
	private static final String TAG = "***";
    /**
     * Файл с данными для подписи.
     */
    public static final String DATA_STREAM_FILE = TEST_PATH + File.separator + "data.file";

    /**
     * True, если подпись отсоединенная. Иначе совмещенная.
     */
    protected boolean detached = false;
    /**
     * Название провайдера.
     */
    protected String providerName = null;
    /**
     * Закрытый ключ для подписи.
     */
    protected PrivateKey privateKey = null;
    /**
     * Цепочка сертификатов для проверки подписи и добавления
     * в подпись.
     */
    protected List<X509Certificate> chain = new ArrayList<X509Certificate>();
    /**
     * Список СОС для проверки подписи.
     */
    protected Set<X509CRL> crlList = new HashSet<X509CRL>();
    /**
     * Список подписываемых аттрибутов для добавления в подпись.
     */
    protected AttributeTable signedAttributes = null;
    /**
     * Список неподписываемых аттрибутов для добавления в подпись.
     */
    protected AttributeTable unsignedAttributes = null;
    /**
     * Список сертификатов для добавления в подпись.
     */
    protected CollectionStore certificateStore = null;
    /**
     * Список СОС для добавления в подпись.
     */
    protected CollectionStore crlStore = null;
    /**
     * True, если следует использовать поток данных и подписи.
     */
    protected boolean useStream = false;
    /**
     * Контейнер подписи.
     */
    protected ISignatureContainer signatureContainer = null;

    /**
     * Скрытый конструктор.
     *
     * @param provider имя провайдера.
     * @param detached True, если подпись отсоединенная.
     * @param useStream True, если следует использовать поток данных и подписи.
     * @throws Exception
     */
    protected Configuration(String provider, boolean detached,
        boolean useStream, ISignatureContainer container) {
        this.detached = detached;
        this.useStream = useStream;
        this.providerName = provider;
        this.signatureContainer = container;
    }

    /**
     * Функция получения названия провайдера.
     *
     * @return название провайдера.
     */
    @Override
    public String getProviderName() {
        return providerName;
    }

    /**
     * Функция получения цепочки сертификатов в виде CertificateHolder.
     *
     * @return цепочка сертификатов X509CertificateHolder.
     */
    @Override
    public Collection<X509CertificateHolder> getChainHolder() {

        Collection<X509CertificateHolder> holders = new ArrayList<X509CertificateHolder>();

        for (X509Certificate cert : chain) {
            try {
                holders.add(new X509CertificateHolder(cert.getEncoded()));
            } catch (Exception e) {
                e.printStackTrace();
            }
        } // for

        return holders;
    }

    /**
     * Функция получения списка СОС в виде CRLHolder.
     *
     * @return списка СОС X509CRLHolder.
     */
    @Override
    public Collection<X509CRLHolder> getCRLsHolder() {

        Collection<X509CRLHolder> holders = new ArrayList<X509CRLHolder>();

        if (crlList != null) {
            for (X509CRL crl : crlList) {
                try {
                    holders.add(new X509CRLHolder(crl.getEncoded()));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } // for
        } // if

        return holders;
    }

    /**
     * Функция получения списка подписываемых аттрибутов, которые
     * можно добавить в подпись.
     *
     * @return список подписываемых аттрибутов.
     * @throws Exception
     */
    @Override
    public AttributeTable getSignedAttributes() throws Exception {
        return signedAttributes;
    }

    /**
     * Функция получения списка неподписываемых аттрибутов, которые
     * можно добавить в подпись.
     *
     * @return список неподписываемых аттрибутов.
     * @throws Exception
     */
    @Override
    public AttributeTable getUnsignedAttributes() throws Exception {
        return unsignedAttributes;
    }

    /**
     * Функция задания списка подписываемых аттрибутов, которые
     * можно добавить в подпись.
     *
     * @param table Таблица аттрибутов.
     */
    @Override
    public void setSignedAttributes(AttributeTable table) {
        signedAttributes = table;
    }

    /**
     * Функция задания списка неподписываемых аттрибутов, которые
     * можно добавить в подпись.
     *
     * @param table Таблица аттрибутов.
     */
    @Override
    public void setUnsignedAttributes(AttributeTable table) {
        unsignedAttributes = table;
    }

    /**
     * Функция задания списка сертификатов для добавления в подпись.
     *
     * @param store Список сертификатов.
     */
    @Override
    public void setCertificateStore(CollectionStore store) {
        certificateStore = store;
    }

    /**
     * Функция задания списка СОС для добавления в подпись.
     *
     * @param store Список СОС.
     */
    @Override
    public void setCRLStore(CollectionStore store) {
        crlStore = store;
    }

    /**
     * Функция получения списка сертификатов для добавления в подпись.
     *
     * @return Список сертификатов.
     */
    @Override
    public CollectionStore getCertificateStore() {
        return certificateStore;
    }

    /**
     * Функция получения списка СОС для добавления в подпись.
     *
     * @return Список СОС.
     */
    @Override
    public CollectionStore getCRLStore() {
        return crlStore;
    }

    /**
     * Загрузка закрытого ключа и цепочки сертификатов из пользовательского
     * контейнера. Конфигурация по умолчанию для провайдера JCP. Провайдер
     * подписи может быть переопределен с помощью системной настройки
     * ru.cryptopro.defaultProv.
     *
     * @param container Описание ключевого контейнера.
     * @param chain Цепочка сертификатов. Заполнится после загрузки хранилища.
     * @return закрытый ключ из контейнера.
     * @throws Exception
     */
    public static PrivateKey loadConfiguration(ISignatureContainer container,
        Collection<X509Certificate> chain) throws Exception {
        return loadConfiguration(ResolveProvider.resolvedStoreProvider, container, chain);
    }

	/**
	 * Загрузка закрытого ключа и цепочки сертификатов из пользовательского
	 * контейнера.
     *
     * @param provider Название криптопрвайдера.
     * @param container Описание ключевого контейнера.
	 * @param chain Цепочка сертификатов. Заполнится после загрузки хранилища.
	 * @return закрытый ключ из контейнера.
	 * @throws Exception
	 * @throws UnrecoverableKeyException
	 */
	public static PrivateKey loadConfiguration(String provider,
        ISignatureContainer container, Collection<X509Certificate> chain)
        throws Exception {

        /**
         * В зависимости от провайдера - JCP или JCSP - используем тип контейнера.
         * JCSP (как и CSP) работает с типом HDIMAGE (или REGISTRY).
         */
		return loadConfiguration(provider,
            (provider.equalsIgnoreCase(JCP.PROVIDER_NAME) ? JCP.HD_STORE_NAME : JCSP_DEFAULT_STORE_TYPE),
            null, null, container.getAlias(), container.getPassword(), chain);
	}
	
	/**
	 * Загрузка закрытого ключа и цепочки сертификатов из пользовательского
	 * контейнера.
     *
     * @param provider Название криптопрвайдера.
     * @param storeType Тип хранилища.
     * @param storeFile Путь к хранилищу.
     * @param storePassword Пароль хранилища.
     * @param alias Идентификатор ключа.
     * @param password Пароль ключа.
	 * @param chain Цепочка сертификатов. Заполнится после загрузки хранилища.
	 * @return закрытый ключ из контейнера.
	 * @throws Exception
	 * @throws UnrecoverableKeyException
	 */
	public static PrivateKey loadConfiguration(String provider, String storeType,
        String storeFile, char[] storePassword, String alias, char[] password,
        Collection<X509Certificate> chain) throws Exception {

		KeyStore keyStore = KeyStore.getInstance(storeType, provider);

        try (FileInputStream is = (storeFile == null) ? null : new FileInputStream(storeFile)) {
            keyStore.load(is, storePassword);
        }

        PrivateKey privateKey;
        if (provider.equalsIgnoreCase(ResolveProvider.ALTERNATIVE_PROVIDER)) {

            JCPProtectionParameter parameter = new JCPProtectionParameter(password);
            JCPPrivateKeyEntry entry = (JCPPrivateKeyEntry) keyStore.getEntry(alias, parameter);

            privateKey = entry.getPrivateKey();

        } // if
        else {
            privateKey = (PrivateKey) keyStore.getKey(alias, password);
        } // else

		// Получаем цепочку сертификатов. 
		List<Certificate> lChain = 
			Arrays.asList(keyStore.getCertificateChain(alias));
	
		// Конвертируем цепочку в X509Certificate.
		Collection<X509Certificate> xChain = 
			Arrays.asList((lChain).toArray(new X509Certificate[lChain.size()]));
		
		chain.addAll(xChain);
		
		return privateKey;
	}

    /**
     * Функция загрузки СОС.
     *
     * @param crlPath Путь к СОС.
     * @throws Exception
     */
    protected void loadCRLs(String crlPath) throws Exception {

        File crlFile = new File(crlPath);

        // Если задан CRL, то читаем его из файла.
        if (crlFile.exists()) {
            try (FileInputStream is = new FileInputStream(crlFile)) {
                X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(is);
                crlList.add(crl);
            }
        } // if
    }
	
	/**
	 * Вывод информации об отдельной подписи.
	 * 
	 * @param signer Подпись.
	 * @param index Индекс подписи.
	 * @param tab Отступ для удобства печати.
	 */
	private static void printSignerInfo(CAdESSigner signer, int index, String tab) {
		
		X509Certificate signerCert = signer.getSignerCertificate();
		
		System.out.println(tab + " Signature #" + index + " (" + 
			CAdESType.getSignatureTypeName(signer.getSignatureType()) + ")" + 
			(signerCert != null ? (" verified by " + signerCert.getSubjectDN()) : "" ));

		if ( signer.getSignatureType().equals(CAdESType.CAdES_X_Long_Type_1) ) {
							
			TimeStampToken signatureTimeStamp = ((CAdESSignerXLT1)signer).getEarliestValidSignatureTimeStampToken();
			TimeStampToken cadesCTimeStamp = ((CAdESSignerXLT1)signer).getEarliestValidCAdESCTimeStampToken();
			
			// if (signatureTimeStamp != null) {
			// 	System.out.println(tab + TAG + " Signature timestamp set: " +
			// 		signatureTimeStamp.getTimeStampInfo().getGenTime());
			// } // if
			//
			// if (cadesCTimeStamp != null) {
			// 	System.out.println(tab + TAG + " CAdES-C timestamp set: " +
			// 		cadesCTimeStamp.getTimeStampInfo().getGenTime());
			// } // if

		} // if

        // printSignerAttributeTableInfo(index,
        //     signer.getSignerSignedAttributes(), "signed");

        // printSignerAttributeTableInfo(index,
        //     signer.getSignerUnsignedAttributes(), "unsigned");

        // printCountersignerInfos(signer.getCAdESCountersignerInfos());
	}
	
	/**
	 * Вывод информации о заверителях отдельной подписи.
	 * 
	 * @param countersigners Список заверителей.
	 */
	private static void printCountersignerInfos(CAdESSigner[] countersigners) {

        System.out.println("$$$ Print counter signature information $$$");

		// Заверяющие подписи.
		int countersignerIndex = 1;
		for (CAdESSigner countersigner : countersigners) {
			printSignerInfo(countersigner, countersignerIndex++, TAG);
		}
	}
	
	/**
	 * Вывод информации о подписи: кто подписал, тип подписи, штампы времени.
	 * 
	 * @param signature CAdES подпись.
	 */
	public static void printSignatureInfo(CAdESSignature signature) {

        System.out.println("$$$ Print signature information $$$");

		// Список подписей.
		int signerIndex = 1;
		for (CAdESSigner signer : signature.getCAdESSignerInfos()) {
			printSignerInfo(signer, signerIndex++, "");
		}
	}

    /**
     * Выводим информацию о случившейся ошибке. Для CAdESException дополнительно
     * выводится код ошибки.
     *
     * @param e Исключение.
     */
    public static void printCAdESException(Exception e) {

        if (e instanceof CAdESException) {
            System.out.println(e.getMessage() + " (" + ((CAdESException)e).getErrorCode() + ")");
        } else if (e.getCause() instanceof CAdESException) {
            CAdESException ex = (CAdESException)e.getCause();
            System.out.println(ex.getMessage() + " (" + ex.getErrorCode() + ")");
        } else {
            e.printStackTrace();
        }
    }

    /**
     * Вывод содержимого таблицы аттрибутов.
     *
     * @param i Номер подписанта.
     * @param table Таблица с аттрибутами.
     * @param type Тип таблицы: "signed" или "unsigned".
     */
    public static void printSignerAttributeTableInfo(int i, AttributeTable table,
        String type) {

        if (table == null) {
            return;
        } // if

        System.out.println("Signer #" + i + " has " + table.size() + " " +
            type + " attributes.");

        Attributes attributeTable = table.toASN1Structure();
        Attribute[] attributes = attributeTable.getAttributes();

        for (Attribute attribute : attributes) {

            System.out.println(" Attribute" +
                "\n\ttype : " + attribute.getAttrType().getId() +
                "\n\tvalue: " + attribute.getAttrValues());

        } // while
    }

    /**
     * Получение некоего списка подписываемых аттрибутов.
     * Будут выданы 1 и 2 аттрибута - время подписи и адрес.
     *
     * @param signTime True, если нужно добавить аттрибут signing-time.
     * @param email True, если нужно добавить аттрибут emailAddress.
     * @return список подписываемых аттрибутов.
     * @throws Exception
     */
    public static AttributeTable getSomeSignedAttributes(boolean signTime,
        boolean email) throws Exception {

        final Hashtable table = new Hashtable();

        if (signTime) {

            Attribute attr = new Attribute(CMSAttributes.signingTime,
                new DERSet(new Time(new Date())));

            table.put(attr.getAttrType(), attr);
        } // if

        if (email) {

            Attribute attr = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_emailAddress,
                new DERSet(new DERIA5String("test@cryptopro.ru")));

            table.put(attr.getAttrType(), attr);

        } // if

        return new  AttributeTable(table);
    }

    /**
     * Получение некоего списка неподписываемых аттрибутов.
     * Будет выдан 1 аттрибут - адрес.
     *
     * @param email True, если нужно добавить аттрибут emailAddress.
     * @return список неподписываемых аттрибутов.
     * @throws Exception
     */
    public static AttributeTable getSomeUnsignedAttributes(boolean email)
        throws Exception {

        return getSomeSignedAttributes(false, email);
    }

    /**
     * Функция определяет, использовать ли поточную модель
     * для подписи/проверки.
     *
     * @return true, если использовать потоки.
     */
    @Override
    public boolean useStream() {
        return useStream;
    }

    /**
     * Функция получения закрытого ключа.
     *
     * @return закрытый ключ.
     */
    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Функция получения сертификата подписи.
     *
     * @return сертификат.
     */
    @Override
    public X509Certificate getCertificate() {
        if (chain != null && chain.size() > 0) {

            Iterator it = chain.iterator();
            if (it.hasNext()) {
                return (X509Certificate) it.next();
            } // if

        } // if

        return null;
    }

    /**
     * Функция получения цепочки сертификатов.
     *
     * @return цепочка сертификатов.
     */
    @Override
    public List<X509Certificate> getChain() {
        return chain;
    }

    /**
     * Функция получения списка СОС.
     *
     * @return список СОС.
     */
    @Override
    public Set<X509CRL> getCRLs() {
        return crlList;
    }

    /**
     * Функция получения потока подписываемых данных.
     *
     * @return поток данных для подписи.
     */
    @Override
    public InputStream getDataStream() throws Exception {
        return useStream() ? new FileInputStream(DATA_STREAM_FILE)
            : new ByteArrayInputStream(DATA);
    }

    /**
     * Функция получения адреса TSA.
     *
     * @return адрес TSA.
     */
    @Override
    public String getTSAAddress() {
        return
           (signatureContainer != null &&
            signatureContainer.getTsaAddress() != null)
            ? signatureContainer.getTsaAddress()
            : TSA_DEFAULT_ADDRESS;
    }

    /**
     * Функция сообщает, отсоединенная ли это подпись.
     *
     * @return True, если подпись отсоединенная.
     */
    @Override
    public boolean detached() {
        return detached;
    }

    @Override
    public String getDigestOid() {

        String privateKeyAlgorithm = privateKey.getAlgorithm();

        if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME) ||
            privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_256_NAME)) {
            return JCP.GOST_DIGEST_2012_256_OID;
        } // if
        else if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME) ||
            privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_512_NAME)) {
            return JCP.GOST_DIGEST_2012_512_OID;
        } // if

        return JCP.GOST_DIGEST_OID;
    }

    @Override
    public String getPublicKeyOid() {

        String privateKeyAlgorithm = privateKey.getAlgorithm();

        if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME) ||
           (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_256_NAME))) {
            return JCP.GOST_PARAMS_SIG_2012_256_KEY_OID;
        } // if
        else if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME) ||
           (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_512_NAME))) {
            return JCP.GOST_PARAMS_SIG_2012_512_KEY_OID;
        } // else

        return JCP.GOST_EL_KEY_OID;

    }

    @Override
    public String getSignatureOid() {

        String privateKeyAlgorithm = privateKey.getAlgorithm();

        if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME) ||
            privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_256_NAME)) {
            return JCP.GOST_SIGN_2012_256_OID;
        } // if
        else if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME) ||
                privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_512_NAME)) {
            return JCP.GOST_SIGN_2012_512_OID;
        } // if

        return JCP.GOST_EL_SIGN_OID;

    }

}
