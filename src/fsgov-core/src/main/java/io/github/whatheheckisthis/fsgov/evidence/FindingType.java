package io.github.whatheheckisthis.fsgov.evidence;

/** Hygiene findings raised over a snapshot independent of any one identity. */
public enum FindingType {
    /** Owner uid does not resolve to any known account. */
    UNOWNED_PATH,
    /** Owning gid does not resolve to any known group. */
    UNKNOWN_GROUP_OWNER,
    /** Named user ACL entry whose qualifier does not resolve. */
    DANGLING_ACL_USER,
    /** Named group ACL entry whose qualifier does not resolve. */
    DANGLING_ACL_GROUP,
    /** Governed group with no effective members. */
    EMPTY_GOVERNED_GROUP,
    /** Path outside every governed share, so no business owner can certify it. */
    UNGOVERNED_PATH,
    /** Other class can write: a directory without the sticky bit, or any file. */
    WORLD_WRITABLE,
    /** Governed path on a mount where ACLs are not enabled. */
    ACL_DISABLED,
    /** Exported to a client with no_root_squash. */
    NO_ROOT_SQUASH,
    /** Group nesting cycle. */
    NESTING_CYCLE
}
