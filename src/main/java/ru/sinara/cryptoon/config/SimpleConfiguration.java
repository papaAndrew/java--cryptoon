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


import ru.sinara.cryptoon.config.container.ISignatureContainer;
import ru.sinara.cryptoon.util.ResolveProvider;

/**
 * Класс конфигуратора для большинства примеров.
 * Хранит и загружает основные параметры для примеров.
 *
 * 24/01/2013
 *
 */
public class SimpleConfiguration extends Configuration {

    /**
     * Конструктор.
     *
     * @param container Описание ключевого контейнера.
     * @param useStream True, если следует использовать поток данных и подписи.
     * @throws Exception
     */
    public SimpleConfiguration(ISignatureContainer container, boolean useStream)
        throws Exception {
        this(container, false, useStream);
    }

    /**
     * Конструктор.
     *
     * @param container Описание ключевого контейнера.
     * @param detached True, если попдись отсоединенная.
     * @param useStream True, если следует использовать поток данных и подписи.
     * @throws Exception
     */
    public SimpleConfiguration(ISignatureContainer container,
        boolean detached, boolean useStream) throws Exception {
        super(ResolveProvider.resolvedStoreProvider, detached, useStream, container);
        privateKey = Configuration.loadConfiguration(providerName, signatureContainer, chain);
        loadCRLs(CRL_PATH);
    }

    /**
     * Функция получения пути к файлу в папке с подписями.
     *
     * @param prefix Возможный префикс в имени файла.
     * Может быть null.
     * @return абсолютный путь и имя файла.
     */
    public static String getTempFileName(String prefix) {
        return TEMP_PATH + "/" + (prefix == null ? "" : prefix) + "CAdESSignature.bin";
    }

}
