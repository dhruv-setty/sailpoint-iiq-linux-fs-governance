package io.github.whatheheckisthis.fsgov.model;

import java.util.Objects;

/**
 * Observed or desired state of one governed path: numeric owner and group,
 * mode, ACL and the file system that holds it.
 */
public record PathEntry(String path, int uid, int gid, PosixMode mode, Acl acl,
                        FilesystemType filesystem, boolean directory, boolean aclEnabled) {

    public PathEntry {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(filesystem, "filesystem");
        if (!path.startsWith("/")) {
            throw new IllegalArgumentException("Path must be absolute: " + path);
        }
        if (acl == null) {
            acl = Acl.fromMode(mode);
        }
    }

    public static PathEntry directory(String path, int uid, int gid, PosixMode mode, Acl acl, FilesystemType fs) {
        return new PathEntry(path, uid, gid, mode, acl, fs, true, true);
    }

    /**
     * Returns a copy carrying the new ACL. The mode follows the ACL as the
     * kernel keeps it: owner and other bits mirror the USER_OBJ and OTHER
     * entries, and the group class bits mirror the mask when one exists,
     * otherwise the GROUP_OBJ entry. Special bits are preserved.
     */
    public PathEntry withAcl(Acl newAcl) {
        PermissionSet owner = newAcl.find(AclTag.USER_OBJ, null, false).map(AclEntry::permissions).orElse(mode.owner());
        PermissionSet other = newAcl.find(AclTag.OTHER, null, false).map(AclEntry::permissions).orElse(mode.other());
        PermissionSet group = newAcl.effectiveMask();
        int special = mode.bits() & 07000;
        PosixMode newMode = new PosixMode(special | PosixMode.of(owner, group, other).bits());
        return new PathEntry(path, uid, gid, newMode, newAcl, filesystem, directory, aclEnabled);
    }
}
