package ru.sinara.cryptoon.core;

import ru.sinara.cryptoon.exception.CryptoOperationException;
import ru.sinara.cryptoon.exception.EntryUnavailableException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public interface Signed {
    byte[] sign(byte[] data);
}
