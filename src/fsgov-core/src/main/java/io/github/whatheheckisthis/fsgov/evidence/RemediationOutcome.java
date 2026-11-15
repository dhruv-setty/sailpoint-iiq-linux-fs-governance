package io.github.whatheheckisthis.fsgov.evidence;

/** Result of checking one revoked item against the state after remediation. */
public enum RemediationOutcome {
    /** The revoked access is no longer present. */
    VERIFIED,
    /** The revoked access is still present. */
    NOT_REMOVED,
    /** The item could not be checked, for example because its share is unknown. */
    INCONCLUSIVE
}
