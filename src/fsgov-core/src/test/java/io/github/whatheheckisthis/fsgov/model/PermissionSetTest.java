package io.github.whatheheckisthis.fsgov.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionSetTest {

    @ParameterizedTest
    @ValueSource(strings = {"---", "r--", "rw-", "r-x", "rwx", "--x", "-w-", "-wx"})
    void textRoundTrips(String text) {
        assertEquals(text, PermissionSet.parse(text).toString());
    }

    @Test
    void octalRoundTrips() {
        for (int i = 0; i <= 7; i++) {
            assertEquals(i, PermissionSet.fromOctalDigit(i).toOctalDigit());
        }
    }

    @Test
    void setAlgebra() {
        PermissionSet rx = PermissionSet.READ_EXECUTE;
        PermissionSet rw = PermissionSet.READ_WRITE;
        assertEquals("rwx", rx.union(rw).toString());
        assertEquals("r--", rx.intersect(rw).toString());
        assertEquals("--x", rx.minus(rw).toString());
        assertTrue(PermissionSet.ALL.containsAll(rx));
        assertFalse(rx.containsAll(rw));
        assertTrue(PermissionSet.NONE.isEmpty());
    }

    @Test
    void rejectsMalformedInput() {
        assertThrows(IllegalArgumentException.class, () -> PermissionSet.parse("rw"));
        assertThrows(IllegalArgumentException.class, () -> PermissionSet.parse("wrx"));
        assertThrows(IllegalArgumentException.class, () -> PermissionSet.fromOctalDigit(8));
    }
}
