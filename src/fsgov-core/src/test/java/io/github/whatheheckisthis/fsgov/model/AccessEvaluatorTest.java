package io.github.whatheheckisthis.fsgov.model;

import io.github.whatheheckisthis.fsgov.Fixtures;
import org.junit.jupiter.api.Test;

import java.util.List;

import static io.github.whatheheckisthis.fsgov.Fixtures.FINANCE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccessEvaluatorTest {

    private final FilesystemSnapshot estate = Fixtures.estate();
    private final AccessEvaluator eval = new AccessEvaluator(estate);

    private String local(String account, String path) {
        return eval.evaluate(account, path, AccessContext.LOCAL).permissions().toString();
    }

    @Test
    void ownerNamedGroupAndOther() {
        assertEquals("rwx", local("finsvc", FINANCE));
        assertEquals("r-x", local("bob", FINANCE));
        assertEquals("---", local("alice", FINANCE));
        assertEquals("rwx", local("root", FINANCE));
    }

    @Test
    void maskLimitsNamedEntries() {
        Acl acl = estate.path(FINANCE).orElseThrow().acl().with(AclEntry.parse("user:alice:rwx"));
        FilesystemSnapshot s = estate.toBuilder().path(estate.path(FINANCE).orElseThrow().withAcl(acl)).build();
        AccessDecision d = new AccessEvaluator(s).evaluate("alice", FINANCE, AccessContext.LOCAL);
        assertEquals("r-x", d.permissions().toString());
        assertTrue(d.source().contains("masked by r-x"));
    }

    @Test
    void namedUserEntryTakesPrecedenceOverGroups() {
        Acl acl = estate.path(FINANCE).orElseThrow().acl().with(AclEntry.parse("user:bob:---"));
        FilesystemSnapshot s = estate.toBuilder().path(estate.path(FINANCE).orElseThrow().withAcl(acl)).build();
        assertEquals("---", new AccessEvaluator(s).evaluate("bob", FINANCE, AccessContext.LOCAL).permissions().toString());
    }

    @Test
    void numericQualifiersResolve() {
        Acl acl = estate.path(FINANCE).orElseThrow().acl().with(AclEntry.parse("group:1003:r-x"));
        FilesystemSnapshot s = estate.toBuilder().path(estate.path(FINANCE).orElseThrow().withAcl(acl)).build();
        assertEquals("r-x", new AccessEvaluator(s).evaluate("carol", FINANCE, AccessContext.LOCAL).permissions().toString());
    }

    @Test
    void rootIsSquashedOverNfsUnlessNoRootSquash() {
        AccessDecision squashed = eval.evaluate("root", FINANCE, AccessContext.nfs("10.20.0.0/16"));
        assertEquals("---", squashed.permissions().toString());
        assertTrue(squashed.source().contains("root_squash"));
        AccessDecision backup = eval.evaluate("root", FINANCE, AccessContext.nfs("backup01"));
        assertEquals("r-x", backup.permissions().toString());
        assertTrue(backup.source().contains("ro export"));
    }

    @Test
    void unexportedClientAndUnknownsGetNothing() {
        assertEquals("---", eval.evaluate("bob", FINANCE, AccessContext.nfs("laptop")).permissions().toString());
        assertEquals("---", local("nobody", FINANCE));
        assertEquals("---", local("bob", "/srv/missing"));
    }

    @Test
    void allSquashMapsEveryoneToAnon() {
        FilesystemSnapshot s = estate.toBuilder()
                .export(new NfsExport(FINANCE, List.of(new NfsClientRule("kiosk", List.of("rw", "all_squash")))))
                .build();
        AccessDecision d = new AccessEvaluator(s).evaluate("finsvc", FINANCE, AccessContext.nfs("kiosk"));
        assertEquals("---", d.permissions().toString());
        assertTrue(d.source().contains("all_squash"));
    }

    @Test
    void owningGroupOnMinimalAclIsNotMasked() {
        FilesystemSnapshot s = estate.toBuilder().account(new Account("audsvc", 980, 0)).build();
        assertEquals("r-x", new AccessEvaluator(s).evaluate("audsvc", Fixtures.AUDIT, AccessContext.LOCAL)
                .permissions().toString());
    }
}
