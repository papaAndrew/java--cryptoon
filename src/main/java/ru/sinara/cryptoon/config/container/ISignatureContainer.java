package ru.sinara.cryptoon.config.container;

/**
 * Служебный интерфейс ISignatureContainer предназначен
 * для создания классов, содержащих контейнеры на различных
 * алгоритмах.
 *
 * 16/12/2013
 *
 */
public interface ISignatureContainer {

    /**
     * Получение алиаса ключа.
     *
     * @return алиас ключа.
     */
    public String getAlias();

    /**
     * Получение пароля для доступа к ключу.
     *
     * @return пароль для доступа к ключу.
     */
    public char[] getPassword();

    /**
     * Получение адреса TSA службы.
     *
     * @return адрес службы.
     */
    public String getTsaAddress();

}
