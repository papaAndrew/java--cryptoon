package ru.sinara.cryptoon.exception;

public class InitFailureException extends Exception {
    public InitFailureException(String message) {
        super(message);
    }
    public InitFailureException(String message, Throwable cause) {
        super(message, cause);
    }
}
