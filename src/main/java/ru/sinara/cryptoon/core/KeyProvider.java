package ru.sinara.cryptoon.core;

import java.security.PrivateKey;
import java.security.cert.Certificate;

public interface KeyProvider {
    PrivateKey getPrivateKey();
    Certificate getCertificate();
}
