package io.github.whatheheckisthis.fsgov.plan;

import io.github.whatheheckisthis.fsgov.Fixtures;
import io.github.whatheheckisthis.fsgov.model.AccessContext;
import io.github.whatheheckisthis.fsgov.model.AccessEvaluator;
import io.github.whatheheckisthis.fsgov.model.AclTag;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.Group;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;
import org.junit.jupiter.api.Test;

import java.util.List;

import static io.github.whatheheckisthis.fsgov.Fixtures.AUDIT;
import static io.github.whatheheckisthis.fsgov.Fixtures.FINANCE;
import static io.github.whatheheckisthis.fsgov.Fixtures.SCRATCH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChangePlannerTest {

    private final FilesystemSnapshot estate = Fixtures.estate();
    private final ChangePlanner planner = new ChangePlanner(Fixtures.catalog());
    private final PlanApplier applier = new PlanApplier();

    @Test
    void grantOfNewGroupCreatesBindsMasksThenAddsMember() {
        ChangePlan plan = planner.plan(estate, List.of(ProvisioningRequest.addGroup("alice", "fs_fin_rw")));
        assertEquals(List.of(
                "groupadd -g 4101 fs_fin_rw",
                "setfacl -n -m default:group:fs_fin_rw:rwx /srv/finance",
                "setfacl -n -m group:fs_fin_rw:rwx /srv/finance",
                "setfacl -n -m mask::rwx /srv/finance",
                "setfacl -n -m default:mask::rwx /srv/finance",
                "gpasswd -a alice fs_fin_rw"), plan.describe());
        assertTrue(plan.warnings().isEmpty());
    }

    @Test
    void applyingGrantGivesExpectedAccess() {
        ChangePlan plan = planner.plan(estate, List.of(ProvisioningRequest.addGroup("alice", "fs_fin_rw")));
        FilesystemSnapshot after = applier.apply(estate, plan);
        assertEquals("rwx", new AccessEvaluator(after).evaluate("alice", FINANCE, AccessContext.LOCAL).permissions().toString());
        assertEquals("2770", after.path(FINANCE).orElseThrow().mode().toOctal());
    }

    @Test
    void replanningAfterApplyIsEmpty() {
        List<ProvisioningRequest> reqs = List.of(
                ProvisioningRequest.addGroup("alice", "fs_fin_rw"),
                ProvisioningRequest.addGroup("carol", "fs_audit_ro"),
                ProvisioningRequest.removeGroup("bob", "fs_fin_ro"),
                ProvisioningRequest.addDirect("carol", FINANCE, PermissionSet.READ_ONLY));
        ChangePlan first = planner.plan(estate, reqs);
        FilesystemSnapshot after = applier.apply(estate, first);
        ChangePlan second = planner.plan(after, reqs);
        assertTrue(second.isNoOp(), () -> "expected no-op, got " + second.describe());
        assertFalse(second.alreadySatisfied().isEmpty());
        assertEquals(after.paths(), applier.apply(after, first).paths());
    }

    @Test
    void existingMembershipIsSatisfied() {
        ChangePlan plan = planner.plan(estate, List.of(ProvisioningRequest.addGroup("bob", "fs_fin_ro")));
        assertTrue(plan.isNoOp());
        assertTrue(plan.alreadySatisfied().contains("bob is already a member of fs_fin_ro"));
    }

    @Test
    void bindingDriftIsRepairedOnGrant() {
        var fin = estate.path(FINANCE).orElseThrow();
        FilesystemSnapshot drifted = estate.toBuilder()
                .path(fin.withAcl(fin.acl().without(AclTag.GROUP, "fs_fin_ro", true)))
                .build();
        ChangePlan plan = planner.plan(drifted, List.of(ProvisioningRequest.addGroup("bob", "fs_fin_ro")));
        assertEquals(List.of("setfacl -n -m default:group:fs_fin_ro:r-x /srv/finance"), plan.describe());
    }

    @Test
    void revocationsAreOrderedBeforeGrants() {
        ChangePlan plan = planner.plan(estate, List.of(
                ProvisioningRequest.addGroup("bob", "fs_audit_ro"),
                ProvisioningRequest.removeGroup("bob", "fs_fin_ro")));
        List<Phase> phases = plan.steps().stream().map(ChangeStep::phase).toList();
        assertEquals(Phase.REVOKE_MEMBERSHIP, phases.get(0));
        assertEquals(Phase.GRANT_MEMBERSHIP, phases.get(phases.size() - 1));
        for (int i = 1; i < phases.size(); i++) {
            assertTrue(phases.get(i - 1).compareTo(phases.get(i)) <= 0);
        }
    }

    @Test
    void conflictingAddAndRemoveKeepsRemoval() {
        ChangePlan plan = planner.plan(estate, List.of(
                ProvisioningRequest.removeGroup("bob", "fs_fin_ro"),
                ProvisioningRequest.addGroup("bob", "fs_fin_ro")));
        assertEquals(List.of("gpasswd -d bob fs_fin_ro"), plan.describe());
        assertTrue(plan.hasWarning(PlanWarning.Code.CONFLICTING_REQUESTS));

        FilesystemSnapshot noBob = estate.toBuilder().group(Group.of("fs_fin_ro", 4100)).build();
        ChangePlan direct = planner.plan(noBob, List.of(
                ProvisioningRequest.addDirect("carol", AUDIT, PermissionSet.READ_ONLY),
                ProvisioningRequest.removeDirect("carol", AUDIT)));
        assertTrue(direct.isNoOp(), "removal already satisfied must still suppress the grant");
        assertTrue(direct.hasWarning(PlanWarning.Code.CONFLICTING_REQUESTS));
    }

    @Test
    void conflictDetectedWhenBothProduceSteps() {
        FilesystemSnapshot withEntry = applier.apply(estate,
                planner.plan(estate, List.of(ProvisioningRequest.addDirect("carol", AUDIT, PermissionSet.READ_ONLY))));
        ChangePlan plan = planner.plan(withEntry, List.of(
                ProvisioningRequest.addDirect("carol", AUDIT, PermissionSet.ALL),
                ProvisioningRequest.removeDirect("carol", AUDIT)));
        assertTrue(plan.hasWarning(PlanWarning.Code.CONFLICTING_REQUESTS));
        assertTrue(plan.steps().stream().noneMatch(s -> s instanceof ChangeStep.SetAclEntry));
        FilesystemSnapshot after = applier.apply(withEntry, plan);
        assertTrue(after.path(AUDIT).orElseThrow().acl().find(AclTag.USER, "carol", false).isEmpty());
    }

    @Test
    void directRevokeRemovesDefaultBeforeAccess() {
        FilesystemSnapshot withEntry = applier.apply(estate,
                planner.plan(estate, List.of(ProvisioningRequest.addDirect("carol", AUDIT, PermissionSet.READ_ONLY))));
        ChangePlan revoke = planner.plan(withEntry, List.of(ProvisioningRequest.removeDirect("carol", AUDIT)));
        ChangeStep first = revoke.steps().get(0);
        assertInstanceOf(ChangeStep.RemoveAclEntry.class, first);
        assertTrue(((ChangeStep.RemoveAclEntry) first).defaultScope());
        assertTrue(revoke.describe().get(1).startsWith("setfacl -n -x user:carol"));
    }

    @Test
    void removeOfAbsentAccessIsSatisfied() {
        ChangePlan plan = planner.plan(estate, List.of(
                ProvisioningRequest.removeGroup("alice", "fs_fin_ro"),
                ProvisioningRequest.removeDirect("alice", FINANCE),
                ProvisioningRequest.removeDirect("alice", "/srv/gone")));
        assertTrue(plan.isNoOp());
        assertEquals(3, plan.alreadySatisfied().size());
    }

    @Test
    void residualAccessThroughNestingIsWarned() {
        FilesystemSnapshot s = estate.toBuilder()
                .group(Group.of("team_ap", 5000, "bob"))
                .group(Group.of("fs_fin_ro", 4100, "bob").withNested("team_ap"))
                .build();
        ChangePlan plan = planner.plan(s, List.of(ProvisioningRequest.removeGroup("bob", "fs_fin_ro")));
        assertTrue(plan.hasWarning(PlanWarning.Code.RESIDUAL_ACCESS));
    }

    @Test
    void warningsForUnknownsAndUnsupportedTargets() {
        ChangePlan plan = planner.plan(estate, List.of(
                ProvisioningRequest.addGroup("ghost", "fs_fin_rw"),
                ProvisioningRequest.addGroup("alice", "not_in_catalog"),
                ProvisioningRequest.addGroup("alice", "fs_scratch_rw"),
                ProvisioningRequest.addDirect("alice", "/srv/nowhere", PermissionSet.READ_ONLY),
                ProvisioningRequest.addDirect("alice", SCRATCH, PermissionSet.READ_ONLY)));
        assertTrue(plan.hasWarning(PlanWarning.Code.ACCOUNT_NOT_FOUND));
        assertTrue(plan.hasWarning(PlanWarning.Code.UNKNOWN_ENTITLEMENT));
        assertTrue(plan.hasWarning(PlanWarning.Code.ACL_NOT_SUPPORTED));
        assertTrue(plan.hasWarning(PlanWarning.Code.PATH_NOT_FOUND));
        assertTrue(plan.steps().stream().noneMatch(st -> st instanceof ChangeStep.AddMembership));
    }

    @Test
    void gidConflictBlocksGroupCreation() {
        FilesystemSnapshot s = estate.toBuilder().group(Group.of("legacy_ops", 4101)).build();
        ChangePlan plan = planner.plan(s, List.of(ProvisioningRequest.addGroup("alice", "fs_fin_rw")));
        assertTrue(plan.hasWarning(PlanWarning.Code.GID_CONFLICT));
        assertTrue(plan.isNoOp());
    }

    @Test
    void missingSharePathBlocksMembership() {
        FilesystemSnapshot s = estate.toBuilder().build();
        ChangePlanner p = new ChangePlanner(io.github.whatheheckisthis.fsgov.model.EntitlementCatalog.of(
                new io.github.whatheheckisthis.fsgov.model.ShareEntitlement("fs_hr_ro", 4400, "/srv/hr",
                        PermissionSet.READ_EXECUTE, true, "hr.owner")));
        ChangePlan plan = p.plan(s, List.of(ProvisioningRequest.addGroup("alice", "fs_hr_ro")));
        assertTrue(plan.hasWarning(PlanWarning.Code.PATH_NOT_FOUND));
        assertTrue(plan.steps().stream().noneMatch(st -> st instanceof ChangeStep.AddMembership));
    }

    @Test
    void sameRequestTwiceProducesOneSetOfSteps() {
        ChangePlan once = planner.plan(estate, List.of(ProvisioningRequest.addGroup("alice", "fs_fin_rw")));
        ChangePlan twice = planner.plan(estate, List.of(
                ProvisioningRequest.addGroup("alice", "fs_fin_rw"),
                ProvisioningRequest.addGroup("alice", "fs_fin_rw")));
        assertEquals(once.steps(), twice.steps());
    }

    @Test
    void requestValidation() {
        assertThrows(IllegalArgumentException.class,
                () -> new ProvisioningRequest("a", Operation.ADD, "shell", "/bin/sh"));
        assertThrows(IllegalArgumentException.class,
                () -> new ProvisioningRequest("a", Operation.ADD, ProvisioningRequest.ATTR_DIRECT_PERMISSIONS, "rwx").directPath());
        ProvisioningRequest r = ProvisioningRequest.addDirect("a", "/srv/a:b", PermissionSet.READ_ONLY);
        assertEquals("/srv/a:b", r.directPath());
        assertEquals("r--", r.directPermissions().toString());
    }
}
