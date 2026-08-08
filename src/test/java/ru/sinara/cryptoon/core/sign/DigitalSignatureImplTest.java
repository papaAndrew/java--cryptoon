package ru.sinara.cryptoon.core.sign;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.Provider;
import java.security.Security;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import ru.CryptoPro.JCSP.JCSP;

class DigitalSignatureImplTest {

    @BeforeAll
    static void setUp() {
        if (Security.getProvider("JCSP") == null) {
            Provider p = new JCSP();
            Security.addProvider(p);
        }
    }

    @Test
    void sign() {
        DigitalSignatureImpl signature = new DigitalSignatureImpl();
        byte[] result = signature.sign();
        assertNotNull(result);
        assertEquals(0, result.length);
    }
}
