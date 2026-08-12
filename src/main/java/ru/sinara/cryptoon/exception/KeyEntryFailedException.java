package ru.sinara.cryptoon.exception;

public class KeyEntryFailedException extends RuntimeException {
    public KeyEntryFailedException(String message) {
        super(message);
    }
    public KeyEntryFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
