package ru.sinara.cryptoon.core;

public interface Signed {
    byte[] sign(byte[] data);
}
