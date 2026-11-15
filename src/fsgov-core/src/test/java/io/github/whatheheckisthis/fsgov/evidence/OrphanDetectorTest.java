package io.github.whatheheckisthis.fsgov.evidence;

import io.github.whatheheckisthis.fsgov.Fixtures;
import io.github.whatheheckisthis.fsgov.model.AclEntry;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.FilesystemType;
import io.github.whatheheckisthis.fsgov.model.Group;
import io.github.whatheheckisthis.fsgov.model.PathEntry;
import io.github.whatheheckisthis.fsgov.model.PosixMode;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OrphanDetectorTest {

    @Test
    void detectsLegacyHygieneProblems() {
        FilesystemSnapshot base = Fixtures.estate();
        PathEntry finance = base.path(Fixtures.FINANCE).orElseThrow();
        FilesystemSnapshot s = base.toBuilder()
                .path(finance.withAcl(finance.acl()
                        .with(AclEntry.parse("user:2077:rwx"))
                        .with(AclEntry.parse("group:fs_retired:r-x"))
                        .with(AclEntry.parse("group:4100:r-x"))))
                .path(PathEntry.directory("/srv/finance/old", 2077, 6001, PosixMode.parse("0777"), null, FilesystemType.EXT4))
                .path(PathEntry.directory("/home/shared", 0, 0, PosixMode.parse("0755"), null, FilesystemType.EXT3))
                .group(Group.of("x", 8001).withNested("y"))
                .group(Group.of("y", 8002).withNested("x"))
                .build();
        List<Finding> findings = new OrphanDetector(s, Fixtures.catalog()).detect();
        Set<FindingType> types = findings.stream().map(Finding::type).collect(Collectors.toSet());
        assertTrue(types.containsAll(Set.of(
                FindingType.UNOWNED_PATH, FindingType.UNKNOWN_GROUP_OWNER, FindingType.DANGLING_ACL_USER,
                FindingType.DANGLING_ACL_GROUP, FindingType.EMPTY_GOVERNED_GROUP, FindingType.UNGOVERNED_PATH,
                FindingType.WORLD_WRITABLE, FindingType.ACL_DISABLED, FindingType.NO_ROOT_SQUASH,
                FindingType.NESTING_CYCLE)), types::toString);
        assertTrue(findings.stream().noneMatch(f -> f.type() == FindingType.DANGLING_ACL_GROUP && f.subject().equals("4100")));
        assertTrue(findings.stream().noneMatch(f -> f.type() == FindingType.WORLD_WRITABLE && f.path().equals(Fixtures.SCRATCH)),
                "sticky world writable directory is acceptable");
        assertEquals(findings.stream().sorted((a, b) -> a.type().compareTo(b.type())).map(Finding::type).toList(),
                findings.stream().map(Finding::type).toList());
    }

    @Test
    void cleanEstateHasOnlyExpectedFindings() {
        List<Finding> findings = new OrphanDetector(Fixtures.estate(), Fixtures.catalog()).detect();
        assertFalse(findings.stream().anyMatch(f -> f.type() == FindingType.UNOWNED_PATH));
        assertTrue(findings.stream().anyMatch(f -> f.type() == FindingType.NO_ROOT_SQUASH && f.subject().equals("backup01")));
    }
}
