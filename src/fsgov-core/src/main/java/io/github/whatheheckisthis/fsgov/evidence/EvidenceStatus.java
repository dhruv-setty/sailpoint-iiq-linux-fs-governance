package io.github.whatheheckisthis.fsgov.evidence;

/** Outcome of comparing desired with actual access for one account and path. */
public enum EvidenceStatus {
    /** Actual equals desired. */
    MATCH,
    /** Actual holds bits that desired does not; a revocation candidate. */
    EXCESS,
    /** Desired holds bits that actual lacks; a provisioning gap. */
    MISSING,
    /** Both: the access differs in each direction. */
    DIVERGENT
}
