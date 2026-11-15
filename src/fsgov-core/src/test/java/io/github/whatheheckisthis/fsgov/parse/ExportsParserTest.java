package io.github.whatheheckisthis.fsgov.parse;

import io.github.whatheheckisthis.fsgov.model.NfsClientRule;
import io.github.whatheheckisthis.fsgov.model.NfsExport;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExportsParserTest {

    @Test
    void parsesLegacyExportsFile() {
        String text = String.join("\n",
                "# legacy finance exports",
                "/srv/finance  10.20.0.0/16(rw,sync,root_squash) \\",
                "              backup01(ro,no_root_squash)",
                "\"/srv/audit share\" -ro,sec=sys auditors(rw) reporting",
                "/srv/public *(ro,all_squash,anonuid=65534)  # world readable",
                "");
        List<NfsExport> exports = new ExportsParser().parse(text);
        assertEquals(3, exports.size());
        NfsExport fin = exports.get(0);
        assertEquals("/srv/finance", fin.path());
        assertEquals(2, fin.clients().size());
        assertFalse(fin.ruleFor("backup01").orElseThrow().rootSquash());
        NfsExport audit = exports.get(1);
        assertEquals("/srv/audit share", audit.path());
        NfsClientRule auditors = audit.ruleFor("auditors").orElseThrow();
        assertTrue(auditors.readWrite());
        assertFalse(audit.ruleFor("reporting").orElseThrow().readWrite());
        assertTrue(exports.get(2).ruleFor("*").orElseThrow().allSquash());
    }

    @Test
    void rejectsMalformedLines() {
        assertThrows(IllegalArgumentException.class, () -> new ExportsParser().parse("\"/srv/x host(rw)"));
        assertThrows(IllegalArgumentException.class, () -> new ExportsParser().parse("/srv/x host(rw"));
    }
}
