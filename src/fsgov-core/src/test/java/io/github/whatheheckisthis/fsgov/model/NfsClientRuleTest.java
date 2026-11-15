package io.github.whatheheckisthis.fsgov.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NfsClientRuleTest {

    @Test
    void defaultsAreReadOnlyWithRootSquash() {
        NfsClientRule r = new NfsClientRule("*", List.of());
        assertFalse(r.readWrite());
        assertTrue(r.rootSquash());
        assertFalse(r.allSquash());
        assertEquals(65534, r.anonUid());
        assertEquals("sys", r.security());
    }

    @Test
    void lastOptionWins() {
        NfsClientRule r = new NfsClientRule("h", List.of("ro", "rw", "root_squash", "no_root_squash", "anonuid=500", "anongid=501", "sec=krb5p"));
        assertTrue(r.readWrite());
        assertFalse(r.rootSquash());
        assertEquals(500, r.anonUid());
        assertEquals(501, r.anonGid());
        assertEquals("krb5p", r.security());
        assertTrue(new NfsClientRule("h", List.of("all_squash")).allSquash());
    }

    @Test
    void exportCoversSubtreeOnly() {
        NfsExport e = new NfsExport("/srv/finance", List.of(new NfsClientRule("h", List.of("rw"))));
        assertTrue(e.covers("/srv/finance"));
        assertTrue(e.covers("/srv/finance/ap"));
        assertFalse(e.covers("/srv/financeold"));
        assertTrue(e.ruleFor("h").isPresent());
        assertFalse(e.ruleFor("other").isPresent());
    }
}
