package io.github.whatheheckisthis.fsgov.evidence;

import io.github.whatheheckisthis.fsgov.model.PermissionSet;

/**
 * One line of certification evidence: who, where, what should be, what is,
 * and the ACL entry or rule that explains the actual state.
 */
public record EvidenceRecord(String account, String path, PermissionSet desired, PermissionSet actual,
                             EvidenceStatus status, String source) {

    /** Excess bits, the access a reviewer is asked to revoke or approve. */
    public PermissionSet excess() {
        return actual.minus(desired);
    }

    public PermissionSet missing() {
        return desired.minus(actual);
    }

    /**
     * Canonical tab separated form. Fields are fixed in order so the bundle
     * digest is reproducible from the same inputs on any platform.
     */
    public String canonical() {
        return String.join("\t", account, path, desired.toString(), actual.toString(), status.name(), source);
    }
}
