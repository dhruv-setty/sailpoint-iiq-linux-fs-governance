package io.github.whatheheckisthis.fsgov.evidence;

import io.github.whatheheckisthis.fsgov.Fixtures;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;
import io.github.whatheheckisthis.fsgov.plan.ChangePlan;
import io.github.whatheheckisthis.fsgov.plan.ChangePlanner;
import io.github.whatheheckisthis.fsgov.plan.PlanApplier;
import io.github.whatheheckisthis.fsgov.plan.ProvisioningRequest;
import io.github.whatheheckisthis.fsgov.plan.RevocationPlanner;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationVerifierTest {

    private static final String CERT = "File share review 2026 Q4";

    private final FilesystemSnapshot estate = Fixtures.estate();
    private final PlanApplier applier = new PlanApplier();

    @Test
    void revokedGroupMembershipIsVerifiedAfterApply() {
        RevokedItem item = new RevokedItem("bob", RevokedItem.Kind.GROUP, "fs_fin_ro", "finance.owner", CERT);
        List<ChangePlan> plans = new RevocationPlanner(Fixtures.catalog()).plan(estate, List.of(item));
        FilesystemSnapshot after = estate;
        for (ChangePlan p : plans) {
            after = applier.apply(after, p);
        }
        RemediationReport report = new RemediationVerifier(Fixtures.catalog())
                .verify(CERT, "digest", estate, after, List.of(item));
        assertTrue(report.allVerified());
        RemediationRecord r = report.records().get(0);
        assertEquals("r-x", r.before().toString());
        assertEquals("---", r.after().toString());
    }

    @Test
    void unappliedRevocationIsReportedNotRemoved() {
        RevokedItem item = new RevokedItem("bob", RevokedItem.Kind.GROUP, "fs_fin_ro", "finance.owner", CERT);
        RemediationReport report = new RemediationVerifier(Fixtures.catalog())
                .verify(CERT, "digest", estate, estate, List.of(item));
        assertFalse(report.allVerified());
        assertEquals(1, report.withOutcome(RemediationOutcome.NOT_REMOVED).size());
    }

    @Test
    void directEntryRevocation() {
        FilesystemSnapshot granted = applier.apply(estate, new ChangePlanner(Fixtures.catalog()).plan(estate,
                List.of(ProvisioningRequest.addDirect("carol", Fixtures.AUDIT, PermissionSet.READ_ONLY))));
        RevokedItem item = new RevokedItem("carol", RevokedItem.Kind.DIRECT, Fixtures.AUDIT, "audit.owner", CERT);
        ChangePlan plan = new RevocationPlanner(Fixtures.catalog()).plan(granted, List.of(item)).get(0);
        FilesystemSnapshot after = applier.apply(granted, plan);
        RemediationReport report = new RemediationVerifier(Fixtures.catalog())
                .verify(CERT, "digest", granted, after, List.of(item));
        assertTrue(report.allVerified());
    }

    @Test
    void unknownGroupIsInconclusive() {
        RevokedItem item = new RevokedItem("bob", RevokedItem.Kind.GROUP, "fs_legacy_ops", "it.owner", CERT);
        RemediationReport report = new RemediationVerifier(Fixtures.catalog())
                .verify(CERT, "digest", estate, estate, List.of(item));
        assertEquals(RemediationOutcome.INCONCLUSIVE, report.records().get(0).outcome());
        assertEquals(64, report.sha256().length());
        assertTrue(report.canonicalText().startsWith("# " + CERT));
    }
}
