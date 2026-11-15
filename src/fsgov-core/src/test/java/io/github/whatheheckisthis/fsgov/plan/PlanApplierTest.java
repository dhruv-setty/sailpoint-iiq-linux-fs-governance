package io.github.whatheheckisthis.fsgov.plan;

import io.github.whatheheckisthis.fsgov.Fixtures;
import io.github.whatheheckisthis.fsgov.model.AclEntry;
import io.github.whatheheckisthis.fsgov.model.AclTag;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlanApplierTest {

    private final FilesystemSnapshot estate = Fixtures.estate();
    private final PlanApplier applier = new PlanApplier();

    @Test
    void createGroupIsIdempotentButRejectsGidMismatch() {
        assertSame(estate, applier.apply(estate, new ChangeStep.CreateGroup("fs_fin_ro", 4100)));
        assertThrows(IllegalStateException.class, () -> applier.apply(estate, new ChangeStep.CreateGroup("fs_fin_ro", 9999)));
        assertThrows(IllegalStateException.class, () -> applier.apply(estate, new ChangeStep.CreateGroup("new", 4100)));
    }

    @Test
    void membershipPreconditions() {
        assertThrows(IllegalStateException.class, () -> applier.apply(estate, new ChangeStep.AddMembership("ghost", "fs_fin_ro")));
        assertThrows(IllegalStateException.class, () -> applier.apply(estate, new ChangeStep.AddMembership("alice", "nope")));
        FilesystemSnapshot s = applier.apply(estate, new ChangeStep.RemoveMembership("alice", "nope"));
        assertEquals(estate.groups(), s.groups());
    }

    @Test
    void aclStepsRequireThePath() {
        assertThrows(IllegalStateException.class, () -> applier.apply(estate,
                new ChangeStep.SetMask("/srv/none", false, PermissionSet.ALL)));
    }

    @Test
    void firstDefaultEntryCopiesBaseEntries() {
        FilesystemSnapshot s = applier.apply(estate,
                new ChangeStep.SetAclEntry(Fixtures.AUDIT, AclEntry.parse("default:group:fs_audit_ro:r-x")));
        var acl = s.path(Fixtures.AUDIT).orElseThrow().acl();
        assertTrue(acl.find(AclTag.USER_OBJ, null, true).isPresent());
        assertTrue(acl.find(AclTag.GROUP_OBJ, null, true).isPresent());
        assertTrue(acl.find(AclTag.OTHER, null, true).isPresent());
    }

    @Test
    void stepRenderingIsStable() {
        assertEquals("setfacl -n -x default:group:g /p",
                new ChangeStep.RemoveAclEntry("/p", AclTag.GROUP, "g", true).equivalentCommand());
        assertEquals("setfacl -n -m default:mask::r-x /p",
                new ChangeStep.SetMask("/p", true, PermissionSet.READ_EXECUTE).equivalentCommand());
        ChangePlan p = new ChangePlan(List.of(new ChangeStep.CreateGroup("g", 1)), List.of(), List.of());
        assertEquals(List.of("groupadd -g 1 g"), p.describe());
    }
}
