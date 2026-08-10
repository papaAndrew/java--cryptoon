package ru.sinara.cryptoon.exception;

public class NotSupportedException extends RuntimeException {
    public NotSupportedException(String message) {
        super(message);
    }
    public NotSupportedException(String message, Throwable cause) {
        super(message, cause);
    }
}
