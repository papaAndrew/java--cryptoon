package ru.sinara.cryptoon.core.jcsp.sign;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.CryptoPro.JCP.Util.JCPInit;

import java.security.*;

import static org.junit.jupiter.api.Assertions.*;
import static ru.sinara.cryptoon.util.ImportFiles.importKeyFromJksFile;
import static ru.sinara.cryptoon.util.ImportFiles.importKeyFromPfxFile;

class JcspImportKeyTest {

    public static final String PFX_KEY_ALIAS = "importPfx_Test";
    public static final String JKS_KEY_ALIAS = "importJks_Test";
    public static final char[] KEY_PASSWORD = "123456".toCharArray();
    public static final String PFX_IN_FILE = "src/test/resources/importPfx_Test.p12";
    public static final char[] FILE_PASSWORD = "123456".toCharArray();
    public static final String JKS_IN_FILE = "src/test/resources/importJks_Test.jks";


    @BeforeAll
    static void setUp() {
        JCPInit.initProviders(true);
    }


    @Test
    void importJks_Test() {
        assertDoesNotThrow(() -> importKeyFromJksFile(JKS_IN_FILE, FILE_PASSWORD, JKS_KEY_ALIAS, KEY_PASSWORD));
    }

    @Test
    void importPfx_Test() {
        assertDoesNotThrow(() -> importKeyFromPfxFile(PFX_IN_FILE, FILE_PASSWORD, PFX_KEY_ALIAS, KEY_PASSWORD));
    }

}
