package io.github.whatheheckisthis.fsgov.model;

import io.github.whatheheckisthis.fsgov.Fixtures;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GroupResolverTest {

    private static FilesystemSnapshot nested() {
        // fs_fin_rw contains team_ap as a nested member; team_ap contains alice.
        return Fixtures.estate().toBuilder()
                .group(Group.of("team_ap", 5000, "alice"))
                .group(Group.of("fs_fin_rw", 4101).withNested("team_ap"))
                .build();
    }

    @Test
    void flattensNestedMembership() {
        GroupResolver r = new GroupResolver(nested());
        assertEquals(Set.of("alice", "team_ap", "fs_fin_rw"), r.effectiveGroups("alice"));
        assertTrue(r.effectiveGids("alice").containsAll(Set.of(1001, 5000, 4101)));
        assertEquals(Set.of("alice"), r.effectiveMembers("fs_fin_rw"));
    }

    @Test
    void reportsAlternatePathsAfterDirectRemoval() {
        FilesystemSnapshot s = nested().toBuilder()
                .group(Group.of("fs_fin_rw", 4101, "alice").withNested("team_ap"))
                .build();
        assertEquals(Set.of("team_ap"), new GroupResolver(s).alternatePathsTo("alice", "fs_fin_rw", "fs_fin_rw"));
    }

    @Test
    void toleratesAndReportsCycles() {
        FilesystemSnapshot s = Fixtures.estate().toBuilder()
                .group(Group.of("a", 7001, "carol").withNested("b"))
                .group(Group.of("b", 7002).withNested("a"))
                .build();
        GroupResolver r = new GroupResolver(s);
        assertTrue(r.effectiveGroups("carol").containsAll(Set.of("a", "b")));
        assertEquals(Set.of("a", "b"), r.cycles());
        assertEquals(Set.of("carol"), r.effectiveMembers("b"));
    }
}
