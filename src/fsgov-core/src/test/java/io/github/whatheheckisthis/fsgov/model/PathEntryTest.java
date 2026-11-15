package io.github.whatheheckisthis.fsgov.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PathEntryTest {

    @Test
    void modeGroupBitsFollowMaskWhenAclExtended() {
        PathEntry p = PathEntry.directory("/srv/x", 0, 0, PosixMode.parse("2750"), null, FilesystemType.XFS);
        PathEntry extended = p.withAcl(p.acl()
                .with(AclEntry.parse("group:fin:rwx"))
                .with(AclEntry.parse("mask::rwx")));
        assertEquals("2770", extended.mode().toOctal());
    }

    @Test
    void requiresAbsolutePath() {
        assertThrows(IllegalArgumentException.class,
                () -> PathEntry.directory("srv/x", 0, 0, PosixMode.parse("0750"), null, FilesystemType.XFS));
    }

    @Test
    void filesystemAclSupport() {
        assertEquals(FilesystemType.AclSupport.MOUNT_OPTION, FilesystemType.EXT3.aclSupport());
        assertEquals(FilesystemType.AclSupport.NATIVE, FilesystemType.XFS.aclSupport());
        assertEquals(FilesystemType.AclSupport.SIDEBAND, FilesystemType.NFS_V3.aclSupport());
    }
}
