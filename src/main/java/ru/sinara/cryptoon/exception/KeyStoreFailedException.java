package ru.sinara.cryptoon.exception;

public class KeyStoreFailedException extends RuntimeException {
    public KeyStoreFailedException(String message) {
        super(message);
    }
    public KeyStoreFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
