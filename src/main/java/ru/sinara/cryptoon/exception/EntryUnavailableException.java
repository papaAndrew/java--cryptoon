package ru.sinara.cryptoon.exception;

public class EntryUnavailableException extends RuntimeException {
    public EntryUnavailableException(String message) {
        super(message);
    }
    public EntryUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
