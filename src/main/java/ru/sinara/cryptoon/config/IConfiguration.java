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

/**
 * Интерфейс для наследования конфигуратором.
 *
 * 24/01/2013
 *
 */
public interface IConfiguration {

    /**
     * Функция получения закрытого ключа.
     *
     * @return закрытый ключ.
     */
    public PrivateKey getPrivateKey();

    /**
     * Функция получения сертификата подписи.
     *
     * @return сертификат.
     */
    public X509Certificate getCertificate();

    /**
     * Функция получения цепочки сертификатов.
     *
     * @return цепочка сертификатов.
     */
    public List<X509Certificate> getChain();

    /**
     * Функция получения цепочки сертификатов в виде CertificateHolder.
     *
     * @return цепочка сертификатов X509CertificateHolder.
     */
    public Collection<X509CertificateHolder> getChainHolder();

    /**
     * Функция получения списка СОС.
     *
     * @return список СОС.
     */
    public Set<X509CRL> getCRLs();

    /**
     * Функция получения списка СОС в виде CRLHolder.
     *
     * @return списка СОС X509CRLHolder.
     */
    public Collection<X509CRLHolder> getCRLsHolder();

    /**
     * Функция задания списка подписываемых аттрибутов, которые
     * можно добавить в подпись.
     *
     * @param table Таблица аттрибутов.
     */
    public void setSignedAttributes(AttributeTable table);

    /**
     * Функция задания списка неподписываемых аттрибутов, которые
     * можно добавить в подпись.
     *
     * @param table Таблица аттрибутов.
     */
    public void setUnsignedAttributes(AttributeTable table);

    /**
     * Функция получения списка подписываемых аттрибутов, которые
     * можно добавить в подпись.
     *
     * @return список подписываемых аттрибутов.
     * @throws Exception
     */
    public AttributeTable getSignedAttributes() throws Exception;

    /**
     * Функция получения списка неподписываемых аттрибутов, которые
     * можно добавить в подпись.
     *
     * @return список неподписываемых аттрибутов.
     * @throws Exception
     */
    public AttributeTable getUnsignedAttributes() throws Exception;

    /**
     * Функция задания списка сертификатов для добавления в подпись.
     *
     * @param store Список сертификатов.
     */
    public void setCertificateStore(CollectionStore<X509Certificate> store);

    /**
     * Функция задания списка СОС для добавления в подпись.
     *
     * @param store Список СОС.
     */
    public void setCRLStore(CollectionStore<X509Certificate> store);

    /**
     * Функция получения списка сертификатов для добавления в подпись.
     *
     * @return Список сертификатов.
     */
    public CollectionStore<X509Certificate> getCertificateStore();

    /**
     * Функция получения списка СОС для добавления в подпись.
     *
     * @return Список СОС.
     */
    public CollectionStore<X509Certificate> getCRLStore();

    /**
     * Функция получения потока подписываемых данных.
     *
     * @return поток данных для подписи.
     */
    InputStream getDataStream() throws Exception;

    /**
     * Функция получения адреса TSA.
     *
     * @return адрес TSA.
     */
    public String getTSAAddress();

    /**
     * Функция сообщает, отсоединенная ли это подпись.
     *
     * @return True, если подпись отсоединенная.
     */
    boolean detached();

    /**
     * Функция получения названия провайдера.
     *
     * @return название провайдера.
     */
    public String getProviderName();

    /**
     * Функция получения OID'а алгоритма хеширования.
     *
     * @return OID алгоритма хеширования.
     */
    public String getDigestOid();

    /**
     * Функция получения OID'а набора параметров открытого ключа.
     *
     * @return OID набора параметров.
     */
    public String getPublicKeyOid();

    /**
     * Функция получения OID'а алгоритма подписи.
     *
     * @return OID алгоритма подписи.
     */
    public String getSignatureOid();

    /**
     * Функция определяет, использовать ли поточную модель
     * для подписи/проверки.
     *
     * @return true, если использовать потоки.
     */
    public boolean useStream();

}
