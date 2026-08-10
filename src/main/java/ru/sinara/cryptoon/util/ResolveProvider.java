/**
 * $RCSfileResolveProvider.java,v $
 * version $Revision: 36379 $
 * created 10.08.2015 15:17 by afevma
 * last modified $Date: 2012-05-30 12:19:27 +0400 (Ср, 30 май 2012) $ by $Author: afevma $
 * <br>
 * Copyright 2004-2015 Crypto-Pro. All rights reserved.
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package ru.sinara.cryptoon.util;

import ru.CryptoPro.AdES.AdESConfig;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.Util.DefaultProvider;
import ru.CryptoPro.ssl.util.cpSSLConfig;

import java.security.Provider;
import java.security.Security;

/**
 * Определение имени провайдера.
 *
 * @author Copyright 2004-2015 Crypto-Pro. All rights reserved.
 * @version 2.5
 */
public class ResolveProvider {

    /**
     * Альтернативный провайдер.
     */
    public static final String ALTERNATIVE_PROVIDER =
        DefaultProvider.ALTERNATIVE_PROVIDER_NAME;

    /**
     * Альтернативный тип контейнера.
     */
    public static final String ALTERNATIVE_HD_IMAGE = "HDIMAGE";

    /**
     * Альтернативный тип контейнера.
     */
    public static final String ALTERNATIVE_REGISTRY = "REGISTRY";

    /**
     * Класс альтернативного провайдера.
     */
    private static final String ALTERNATIVE_PROVIDER_CLASS = "ru.CryptoPro.JCSP.JCSP";

    /**
     * Флаг использования sspiSSL.
     */
    private static final String SSPI_ENABLED = "ru.CryptoPro.SSPIEnabled";
    /**
     * Определение провайдера для обращения к контейнеру,
     * хеширования, подписи и шифрования.
     *
     * @return имя провайдера.
     */
    private static String resolveProvider() {

        // Проверяем, не был ли задан другой провайдер подписи, например,
        // Java CSP.
        return System.getProperty(AdESConfig.DEFAULT_PROVIDER, JCP.PROVIDER_NAME);

    }

    /**
     * Определение провайдера контейнера для TLS.
     *
     * @return имя провайдера.
     */
    private static String resolveTlsProvider() {

        // Проверяем, не был ли задан другой провайдер подписи, например,
        // Java CSP.
        return System.getProperty(cpSSLConfig.DEFAULT_PROVIDER, JCP.PROVIDER_NAME);

    }

    /**
     * Проверка, используется ли sspiSSL.
     *
     * @return true, если используется sspiSSL.
     */
    private static boolean isSSPIEnabled() {
        String result = System.getProperty(SSPI_ENABLED, "false");
        return result.equalsIgnoreCase("true");
    }
    /**
     * Провайдер для обращения к контейнеру, хеширования,
     * подписи и шифрования.
     */
    public static final String resolvedStoreProvider = resolveProvider();

    /**
     * Провайдер контейнера для TLS.
     */
    public static final String resolvedTlsProvider = resolveTlsProvider();

    /**
     * Флаг, сообщающий о задействованном Java CSP
     * (командная строка).
     */
    public static final boolean JCSPEnabled = isJCSPEnabled();

    /**
     * Флаг, сообщающий о задействованном SSPI
     * (командная строка).
     */
    public static final boolean SSPIEnabled = isSSPIEnabled();

    /**
     * Флаг, сообщающий о задействованном Java CSP
     * (командная строка) для TLS.
     */
    public static final boolean JCSPEnabledForTls = JCSPEnabled &&
        resolvedTlsProvider.equalsIgnoreCase(ALTERNATIVE_PROVIDER);

    /**
     * Флаг использования ГОСТ 2012 для JCP или Java CSP.
     * По умолчанию всегда true; сделано так для JCP.
     */
    // Гост 2012 есть всегда - флаг не нужен. JCP-1082
    // public static final boolean JCSPGost2012Enabled =
    // System.getProperty("gost2012.enabled", "true").equalsIgnoreCase("true");

    /**
     * Проверка, используется ли Java CSP.
     *
     * @return true, если используется Java CSP.
     */
    private synchronized static boolean isJCSPEnabled() {

        return resolvedStoreProvider != null &&
            resolvedStoreProvider.equalsIgnoreCase(ALTERNATIVE_PROVIDER);

    }

    /**
     * Вставка провайдера Java CSP первым для того, чтобы
     * корректно декодировать открытый ключ.
     *
     */
    public static void insertJavaCSPProvider() {
        insertProvider(ALTERNATIVE_PROVIDER, ALTERNATIVE_PROVIDER_CLASS, 1);
    }

    /**
     * Вставка провайдера первым для того, чтобы корректно
     * декодировать открытый ключ.
     *
     * @param providerName Имя провайдера.
     * @param providerClassName Класс провайдера.
     */
    public static synchronized void insertProvider(String providerName, String providerClassName, int index) {

        // Должен быть установлен, чтобы менять его положение
        if (Security.getProvider(providerName) != null) {

            Security.removeProvider(providerName); // сменим место провайдера в списке
            Provider providerObject;

            try {
                Class providerClass = Class.forName(providerClassName, false, ResolveProvider.class.getClassLoader());
                providerObject = (Provider) providerClass.newInstance();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
                throw new RuntimeException("Provider " + providerName + " not found");
            } catch (InstantiationException e) {
                e.printStackTrace();
                throw new RuntimeException("Provider " + providerName + " not instantiated");
            } catch (IllegalAccessException e) {
                e.printStackTrace();
                throw new RuntimeException("Provider " + providerName + " not instantiated");
            }

            int position = Security.insertProviderAt(providerObject, index); // ставим провайдер на index (1) место
            if (position != index) {
                throw new RuntimeException("Invalid provider position - " + providerName);
            } // if

        } // if
        else {
            throw new RuntimeException("Provider " + providerName + " not found (Security).");
        } // else

    }

}
