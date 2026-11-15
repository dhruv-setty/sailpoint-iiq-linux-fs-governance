package io.github.whatheheckisthis.fsgov.plan;

import io.github.whatheheckisthis.fsgov.Fixtures;
import io.github.whatheheckisthis.fsgov.model.AclTag;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChangePlanCodecTest {

    private final ChangePlanCodec codec = new ChangePlanCodec();

    @Test
    void roundTripsEveryStepKind() {
        List<ChangeStep> steps = List.of(
                new ChangeStep.RemoveAclEntry("/srv/a", AclTag.USER, "carol", true),
                new ChangeStep.RemoveMembership("bob", "fs_fin_ro"),
                new ChangeStep.CreateGroup("fs_fin_rw", 4101),
                new ChangeStep.SetAclEntry("/srv/finance", io.github.whatheheckisthis.fsgov.model.AclEntry.parse("default:group:fs_fin_rw:rwx")),
                new ChangeStep.SetMask("/srv/finance", false, PermissionSet.ALL),
                new ChangeStep.AddMembership("alice", "fs_fin_rw"));
        String text = codec.encode(steps);
        assertTrue(text.startsWith(ChangePlanCodec.HEADER + "\n"));
        assertEquals(steps, codec.decode(text));
    }

    @Test
    void roundTripsAPlannedChange() {
        ChangePlan plan = new ChangePlanner(Fixtures.catalog()).plan(Fixtures.estate(),
                List.of(ProvisioningRequest.addGroup("alice", "fs_fin_rw")));
        assertEquals(plan.steps(), codec.decode(codec.encode(plan.steps())));
    }

    @Test
    void rejectsInjectionAndMalformedInput() {
        assertThrows(IllegalArgumentException.class,
                () -> codec.encode(List.of(new ChangeStep.AddMembership("alice\nADD_MEMBER\tmallory", "wheel"))));
        assertThrows(IllegalArgumentException.class, () -> codec.decode("no header\n"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> codec.decode(ChangePlanCodec.HEADER + "\nADD_MEMBER\talice\n"));
        assertTrue(e.getMessage().startsWith("Line 2"));
        assertThrows(IllegalArgumentException.class, () -> codec.decode(ChangePlanCodec.HEADER + "\nRUN\tanything\n"));
    }
}
