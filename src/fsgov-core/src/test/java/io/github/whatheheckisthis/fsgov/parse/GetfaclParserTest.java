package io.github.whatheheckisthis.fsgov.parse;

import io.github.whatheheckisthis.fsgov.model.AclTag;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GetfaclParserTest {

    private static final String SAMPLE = String.join("\n",
            "# file: srv/finance",
            "# owner: finsvc",
            "# group: finsvc",
            "# flags: -s-",
            "user::rwx",
            "group::r-x",
            "group:fs_fin_ro:r-x",
            "group:fs_fin_rw:rwx\t#effective:r-x",
            "mask::r-x",
            "other::---",
            "default:user::rwx",
            "default:group::r-x",
            "default:group:fs_fin_rw:rwx",
            "default:mask::rwx",
            "default:other::---",
            "",
            "# file: /srv/audit",
            "# owner: root",
            "# group: root",
            "user::rwx",
            "group::r-x",
            "other::---");

    @Test
    void parsesMultipleBlocks() {
        List<ParsedAcl> parsed = new GetfaclParser().parse(SAMPLE);
        assertEquals(2, parsed.size());
        ParsedAcl fin = parsed.get(0);
        assertEquals("/srv/finance", fin.path());
        assertEquals("finsvc", fin.owner());
        assertEquals("-s-", fin.flags());
        assertEquals("rwx", fin.acl().find(AclTag.GROUP, "fs_fin_rw", false).orElseThrow().permissions().toString());
        assertEquals(5, fin.acl().defaultEntries().size());
        assertTrue(parsed.get(1).acl().isMinimal());
        assertEquals("root", parsed.get(1).group());
    }

    @Test
    void reportsLineNumbers() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new GetfaclParser().parse("# file: x\nuser::rwz\n"));
        assertTrue(e.getMessage().startsWith("Line 2"));
        assertThrows(IllegalArgumentException.class, () -> new GetfaclParser().parse("user::rwx\n"));
    }
}
