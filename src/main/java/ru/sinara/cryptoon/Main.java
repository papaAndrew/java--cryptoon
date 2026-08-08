package ru.sinara.cryptoon;

import java.security.Provider;
import java.security.Security;
import ru.CryptoPro.JCSP.JCSP;

public class Main {
    public static void main(String[] args) {

        if (Security.getProvider("JCSP") == null) {
            Provider p = new JCSP();
            Security.addProvider(p);
        }
    }
}
