package io.github.whatheheckisthis.fsgov.evidence;

import io.github.whatheheckisthis.fsgov.Fixtures;
import io.github.whatheheckisthis.fsgov.model.AccessContext;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;
import io.github.whatheheckisthis.fsgov.plan.ChangePlanner;
import io.github.whatheheckisthis.fsgov.plan.PlanApplier;
import io.github.whatheheckisthis.fsgov.plan.ProvisioningRequest;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static io.github.whatheheckisthis.fsgov.Fixtures.AUDIT;
import static io.github.whatheheckisthis.fsgov.Fixtures.FINANCE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccessDifferTest {

    private final FilesystemSnapshot estate = Fixtures.estate();

    @Test
    void classifiesExcessMissingMatchAndDivergent() {
        EvidenceBundle b = new AccessDiffer(estate).diff("Q4 finance share review",
                List.of(new DesiredAccess("alice", FINANCE, PermissionSet.READ_EXECUTE),
                        new DesiredAccess("finsvc", FINANCE, PermissionSet.ALL),
                        new DesiredAccess("carol", AUDIT, PermissionSet.READ_WRITE)),
                Fixtures.accounts(), Set.of(FINANCE, AUDIT));
        assertEquals(EvidenceStatus.EXCESS, find(b, "bob", FINANCE).status());
        assertEquals(EvidenceStatus.MISSING, find(b, "alice", FINANCE).status());
        assertEquals(EvidenceStatus.MATCH, find(b, "finsvc", FINANCE).status());
        assertEquals("r-x", find(b, "bob", FINANCE).excess().toString());
        assertEquals("rw-", find(b, "carol", AUDIT).missing().toString());
        assertEquals(EvidenceStatus.DIVERGENT, AccessDiffer.status(PermissionSet.READ_WRITE, PermissionSet.READ_EXECUTE));
        assertTrue(b.records().stream().noneMatch(r -> r.account().equals("alice") && r.path().equals(AUDIT)));
    }

    @Test
    void remediationClosesTheLoop() {
        ChangePlanner planner = new ChangePlanner(Fixtures.catalog());
        FilesystemSnapshot after = new PlanApplier().apply(estate,
                planner.plan(estate, List.of(ProvisioningRequest.removeGroup("bob", "fs_fin_ro"))));
        EvidenceBundle b = new AccessDiffer(after).diff("verify", List.of(), Set.of("bob"), Set.of(FINANCE));
        assertTrue(b.withStatus(EvidenceStatus.EXCESS).isEmpty());
    }

    @Test
    void digestIsDeterministicAndSensitive() {
        AccessDiffer d = new AccessDiffer(estate);
        EvidenceBundle a = d.diff("c1", List.of(), Fixtures.accounts(), Set.of(FINANCE));
        EvidenceBundle b = d.diff("c1", List.of(), Set.of("carol", "bob", "alice"), Set.of(FINANCE));
        EvidenceBundle c = d.diff("c2", List.of(), Fixtures.accounts(), Set.of(FINANCE));
        assertEquals(a.sha256(), b.sha256());
        assertNotEquals(a.sha256(), c.sha256());
        assertEquals(64, a.sha256().length());
        assertTrue(a.canonicalText().startsWith("# c1\n"));
        assertEquals("c1", a.label());
    }

    @Test
    void nfsContextEvidenceReflectsSquash() {
        EvidenceBundle b = new AccessDiffer(estate, AccessContext.nfs("10.20.0.0/16"))
                .diff("nfs", List.of(), Set.of("root", "bob"), Set.of(FINANCE));
        assertTrue(b.records().stream().noneMatch(r -> r.account().equals("root")));
        assertEquals(EvidenceStatus.EXCESS, find(b, "bob", FINANCE).status());
    }

    private static EvidenceRecord find(EvidenceBundle b, String account, String path) {
        return b.records().stream().filter(r -> r.account().equals(account) && r.path().equals(path))
                .findFirst().orElseThrow(() -> new AssertionError("no record for " + account + " " + path));
    }
}
