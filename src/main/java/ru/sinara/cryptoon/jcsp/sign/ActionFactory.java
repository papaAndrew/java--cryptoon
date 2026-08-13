package ru.sinara.cryptoon.jcsp.sign;


public interface ActionFactory {

    DigitalSignature createPkcsDetached(String alias, char[] password);
}
