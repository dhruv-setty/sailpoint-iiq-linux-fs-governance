package io.github.whatheheckisthis.fsgov.evidence;

import io.github.whatheheckisthis.fsgov.Fixtures;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.Group;
import io.github.whatheheckisthis.fsgov.model.AclEntry;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;
import io.github.whatheheckisthis.fsgov.plan.ChangePlan;
import io.github.whatheheckisthis.fsgov.plan.ChangePlanner;
import io.github.whatheheckisthis.fsgov.plan.PlanApplier;
import io.github.whatheheckisthis.fsgov.plan.ProvisioningRequest;
import io.github.whatheheckisthis.fsgov.plan.RevocationPlanner;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationVerifierTest {

    private static final String CERT = "File share review 2026 Q4";
    private static final Instant AT = Instant.parse("2026-11-15T02:00:00Z");

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
                .verify(CERT, "digest", AT, estate, after, List.of(item));
        assertTrue(report.allVerified());
        RemediationRecord r = report.records().get(0);
        assertEquals("r-x", r.before().toString());
        assertEquals("---", r.after().toString());
    }

    @Test
    void unappliedRevocationIsReportedNotRemoved() {
        RevokedItem item = new RevokedItem("bob", RevokedItem.Kind.GROUP, "fs_fin_ro", "finance.owner", CERT);
        RemediationReport report = new RemediationVerifier(Fixtures.catalog())
                .verify(CERT, "digest", AT, estate, estate, List.of(item));
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
                .verify(CERT, "digest", AT, granted, after, List.of(item));
        assertTrue(report.allVerified());
    }

    @Test
    void unknownGroupIsInconclusive() {
        RevokedItem item = new RevokedItem("bob", RevokedItem.Kind.GROUP, "fs_legacy_ops", "it.owner", CERT);
        RemediationReport report = new RemediationVerifier(Fixtures.catalog())
                .verify(CERT, "digest", AT, estate, estate, List.of(item));
        assertEquals(RemediationOutcome.INCONCLUSIVE, report.records().get(0).outcome());
        assertEquals(64, report.sha256().length());
        assertTrue(report.canonicalText().startsWith("# " + CERT));
    }

    @Test
    void nestedMembershipIsNotRemoved() {
        FilesystemSnapshot nested = estate.toBuilder()
                .group(Group.of("team_ap", 5000, "bob"))
                .group(Group.of("fs_fin_ro", 4100, "bob").withNested("team_ap"))
                .build();
        RevokedItem item = new RevokedItem("bob", RevokedItem.Kind.GROUP, "fs_fin_ro", "finance.owner", CERT);
        ChangePlan plan = new RevocationPlanner(Fixtures.catalog()).plan(nested, List.of(item)).get(0);
        FilesystemSnapshot after = applier.apply(nested, plan);
        RemediationRecord r = new RemediationVerifier(Fixtures.catalog())
                .verify(CERT, "digest", AT, nested, after, List.of(item)).records().get(0);
        assertEquals(RemediationOutcome.NOT_REMOVED, r.outcome());
        assertTrue(r.detail().contains("team_ap"), r.detail());
        assertEquals("r-x", r.after().toString());
    }

    @Test
    void missingAfterDataIsInconclusiveNotVerified() {
        RevokedItem item = new RevokedItem("bob", RevokedItem.Kind.GROUP, "fs_fin_ro", "finance.owner", CERT);
        FilesystemSnapshot noPath = FilesystemSnapshot.builder()
                .account(estate.account("bob").orElseThrow())
                .build();
        FilesystemSnapshot noAccount = estate.toBuilder().build();
        RemediationVerifier v = new RemediationVerifier(Fixtures.catalog());
        assertEquals(RemediationOutcome.INCONCLUSIVE,
                v.verify(CERT, "d", AT, estate, noPath, List.of(item)).records().get(0).outcome());
        RevokedItem ghost = new RevokedItem("ghost", RevokedItem.Kind.GROUP, "fs_fin_ro", "finance.owner", CERT);
        assertEquals(RemediationOutcome.INCONCLUSIVE,
                v.verify(CERT, "d", AT, estate, noAccount, List.of(ghost)).records().get(0).outcome());
    }

    @Test
    void remainingDefaultEntryIsNotRemoved() {
        var audit = estate.path(Fixtures.AUDIT).orElseThrow();
        FilesystemSnapshot inheritOnly = estate.toBuilder()
                .path(audit.withAcl(audit.acl().with(AclEntry.parse("default:user::rwx"))
                        .with(AclEntry.parse("default:group::r-x"))
                        .with(AclEntry.parse("default:other::---"))
                        .with(AclEntry.parse("default:user:carol:r--"))
                        .with(AclEntry.parse("default:mask::r--"))))
                .build();
        RevokedItem item = new RevokedItem("carol", RevokedItem.Kind.DIRECT, Fixtures.AUDIT, "audit.owner", CERT);
        RemediationRecord r = new RemediationVerifier(Fixtures.catalog())
                .verify(CERT, "d", AT, inheritOnly, inheritOnly, List.of(item)).records().get(0);
        assertEquals(RemediationOutcome.NOT_REMOVED, r.outcome());
        assertTrue(r.detail().contains("(default)"));
    }

    @Test
    void digestIsReproducibleFromTheSameInputs() {
        RevokedItem item = new RevokedItem("bob", RevokedItem.Kind.GROUP, "fs_fin_ro", "finance.owner", CERT);
        RemediationVerifier v = new RemediationVerifier(Fixtures.catalog());
        RemediationReport first = v.verify(CERT, "digest", AT, estate, estate, List.of(item));
        RemediationReport second = v.verify(CERT, "digest", AT, estate, estate, List.of(item));
        assertEquals(first.sha256(), second.sha256());
        assertEquals(AT, first.capturedAt());
        RemediationReport later = v.verify(CERT, "digest", AT.plusSeconds(60), estate, estate, List.of(item));
        assertFalse(first.sha256().equals(later.sha256()), "capture time is part of the evidence");
    }
}
