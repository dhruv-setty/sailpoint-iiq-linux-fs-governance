package io.github.whatheheckisthis.fsgov.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PosixModeTest {

    @ParameterizedTest
    @CsvSource({
        "drwxr-x---, 0750",
        "drwxrws---, 2770",
        "drwxrwxrwt, 1777",
        "-rwsr-xr-x, 4755",
        "rwxr-S---, 2740",
        "-rw-r--r-T, 1644"
    })
    void parsesSymbolicForm(String symbolic, String octal) {
        assertEquals(octal, PosixMode.parse(symbolic).toOctal());
    }

    @Test
    void parsesOctalAndExposesClasses() {
        PosixMode m = PosixMode.parse("2750");
        assertEquals("rwx", m.owner().toString());
        assertEquals("r-x", m.group().toString());
        assertEquals("---", m.other().toString());
        assertTrue(m.setgid());
        assertFalse(m.setuid());
        assertFalse(m.sticky());
        assertEquals("0750", PosixMode.parse("750").toOctal());
    }

    @Test
    void withGroupKeepsSpecialBits() {
        PosixMode m = PosixMode.parse("2750").withGroup(PermissionSet.ALL);
        assertEquals("2770", m.toString());
    }

    @Test
    void rejectsGarbage() {
        assertThrows(IllegalArgumentException.class, () -> PosixMode.parse("rwx"));
        assertThrows(IllegalArgumentException.class, () -> PosixMode.parse("rwxrwxrwq"));
        assertThrows(IllegalArgumentException.class, () -> new PosixMode(010000));
    }
}
