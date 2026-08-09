package ru.sinara.cryptoon.core.jcsp;

import ru.CryptoPro.JCP.JCP;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public enum SignAlgorithm {
    SIGN_2012_256(JCP.CRYPTOPRO_SIGN_2012_256_NAME),
    SIGN_2012_512(JCP.CRYPTOPRO_SIGN_2012_512_NAME);

    private final String value;

    private static final Map<String, SignAlgorithm> BY_VALUE = Arrays.stream(values())
                .collect(
                        LinkedHashMap::new,
                        (m, v) -> m.put(v.value, v),
                        LinkedHashMap::putAll);

    SignAlgorithm(String value) {
        this.value = value;
    }

    public static SignAlgorithm fromValue(String value) {
        return BY_VALUE.get(value);
    }

    public String getValue() {
        return value;
    }
}
