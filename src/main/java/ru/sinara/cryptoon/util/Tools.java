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
package ru.sinara.cryptoon.util;

import java.text.DecimalFormat;

/**
 * Класс с различными служебными функциями, используемыми в примерах.
 *
 * 30/04/2013
 *
 */
public class Tools {

    /**
     * Вывод информации о результате операции.
     *
     * @param message Описание результата.
     * @param value Значение измеряемого параметра.
     * @param size Единица измерения.
     */
    public static void printInfo(String message, double value, String size) {
        DecimalFormat decFormat = new DecimalFormat("#.###");
        System.out.println(message + decFormat.format(value) + " " + size);
    }

}
