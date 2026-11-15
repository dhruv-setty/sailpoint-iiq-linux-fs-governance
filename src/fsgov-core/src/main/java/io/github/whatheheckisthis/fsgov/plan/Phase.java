package io.github.whatheheckisthis.fsgov.plan;

/**
 * Execution phases. Revocations run before grants so that a plan which both
 * removes and adds access never leaves a window holding both, which matters
 * for separation of duties. Within grants, a group exists and is bound to its
 * path before anyone is added to it, so access appears in one step.
 */
public enum Phase {
    REVOKE_ACL,
    REVOKE_MEMBERSHIP,
    CREATE_GROUP,
    GRANT_ACL,
    SET_MASK,
    GRANT_MEMBERSHIP
}
