package ru.sinara.cryptoon.core;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public interface Signed {
    byte[] sign(byte[] data) throws Exception;
}
