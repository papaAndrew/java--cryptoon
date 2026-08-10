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
package ru.sinara.cryptoon.config.container;

import CAdES.configuration.Configuration;

/**
 * Служебный класс Container2012_512 предоставляет
 * алиас и пароль для доступа к контейнеру  с ключом
 * подписи на алгоритме ГОСТ Р 34.10-2012 (512 бит).
 *
 * 16/12/2013
 *
 */
public class Container2012_512 implements ISignatureContainer {

    @Override
    public String getAlias() {
        return "unixCadesTestCerts2012-Usr512";
    }

    @Override
    public char[] getPassword() {
        return "c3".toCharArray();
    }

    @Override
    public String getTsaAddress() {
        return Configuration.TSA_DEFAULT_ADDRESS;
    }
}
