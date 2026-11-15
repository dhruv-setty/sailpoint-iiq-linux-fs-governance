package io.github.whatheheckisthis.fsgov.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AclTest {

    @Test
    void parsesEntriesIncludingDefaultsAndComments() {
        AclEntry e = AclEntry.parse("default:group:fs_fin_rw:rwx");
        assertTrue(e.defaultScope());
        assertEquals(AclTag.GROUP, e.tag());
        assertEquals("fs_fin_rw", e.qualifier());
        AclEntry masked = AclEntry.parse("user:alice:rwx\t#effective:r-x");
        assertEquals("user:alice:rwx", masked.toText());
        assertEquals(AclTag.USER_OBJ, AclEntry.parse("u::rw-").tag());
        assertTrue(AclEntry.parse("d:m::r-x").defaultScope());
    }

    @Test
    void rejectsInvalidEntries() {
        assertThrows(IllegalArgumentException.class, () -> AclEntry.parse("user:alice"));
        assertThrows(IllegalArgumentException.class, () -> AclEntry.parse("bogus::rwx"));
        assertThrows(IllegalArgumentException.class, () -> AclEntry.access(AclTag.MASK, "x", PermissionSet.ALL));
        assertThrows(IllegalArgumentException.class, () -> AclEntry.access(AclTag.GROUP, "", PermissionSet.ALL));
    }

    @Test
    void minimalAclFromModeHasNoMask() {
        Acl acl = Acl.fromMode(PosixMode.parse("0750"));
        assertTrue(acl.isMinimal());
        assertEquals("r-x", acl.effectiveMask().toString());
        assertEquals("user::rwx\ngroup::r-x\nother::---\n", acl.toText());
    }

    @Test
    void withReplacesSameSlotAndWithoutRemoves() {
        Acl acl = Acl.fromMode(PosixMode.parse("0750"))
                .with(AclEntry.parse("group:fin:r-x"))
                .with(AclEntry.parse("group:fin:rwx"));
        assertEquals(1, acl.entries().stream().filter(e -> e.tag() == AclTag.GROUP).count());
        assertEquals("rwx", acl.find(AclTag.GROUP, "fin", false).orElseThrow().permissions().toString());
        Acl removed = acl.without(AclTag.GROUP, "fin", false);
        assertFalse(removed.hasNamedEntries(false));
        assertNotEquals(acl, removed);
    }

    @Test
    void computedMaskIsUnionOfGroupClass() {
        Acl acl = Acl.of(List.of(
                AclEntry.parse("user::rwx"),
                AclEntry.parse("user:alice:r--"),
                AclEntry.parse("group::r-x"),
                AclEntry.parse("group:fin:-w-"),
                AclEntry.parse("other::---")));
        assertEquals("rwx", acl.computedMask(false).toString());
        assertEquals("---", acl.computedMask(true).toString());
    }

    @Test
    void canonicalOrderAndEquality() {
        Acl a = Acl.of(List.of(AclEntry.parse("other::---"), AclEntry.parse("user::rwx"), AclEntry.parse("group::r-x")));
        Acl b = Acl.fromMode(PosixMode.parse("0750"));
        assertEquals(b, a);
        assertEquals(b.hashCode(), a.hashCode());
        assertEquals(AclTag.USER_OBJ, a.entries().get(0).tag());
    }

    @Test
    void tagHelpers() {
        assertTrue(AclTag.GROUP_OBJ.isMaskedClass());
        assertFalse(AclTag.OTHER.isMaskedClass());
        assertTrue(AclTag.USER.isNamed());
        assertEquals(AclTag.OTHER, AclTag.of("o", false));
        assertEquals(AclTag.GROUP_OBJ, AclTag.of("g", false));
    }
}
