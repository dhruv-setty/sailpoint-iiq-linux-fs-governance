package io.github.whatheheckisthis.fsgov.model;

/**
 * File system families found on legacy Linux estates, with the way each one
 * exposes POSIX.1e ACLs.
 */
public enum FilesystemType {
    /** ext3: ACLs require the {@code acl} mount option on older kernels and distributions. */
    EXT3(AclSupport.MOUNT_OPTION),
    /** ext4: ACLs are on by default on current kernels, but legacy fstab entries may still set {@code noacl}. */
    EXT4(AclSupport.MOUNT_OPTION),
    /** XFS: ACLs are always available. */
    XFS(AclSupport.NATIVE),
    /** NFSv3 client mount: ACLs travel through the NFSACL side band protocol, not NFSv3 itself. */
    NFS_V3(AclSupport.SIDEBAND);

    /** How ACL support is obtained on a file system family. */
    public enum AclSupport { NATIVE, MOUNT_OPTION, SIDEBAND }

    private final AclSupport aclSupport;

    FilesystemType(AclSupport aclSupport) {
        this.aclSupport = aclSupport;
    }

    public AclSupport aclSupport() {
        return aclSupport;
    }
}
