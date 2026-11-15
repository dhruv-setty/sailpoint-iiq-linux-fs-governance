package io.github.whatheheckisthis.fsgov.evidence;

import java.util.Objects;

/**
 * One certification item a reviewer revoked: a governed group membership or
 * a direct ACL entry, with the reviewer and campaign that decided it.
 */
public record RevokedItem(String account, Kind kind, String target, String reviewer, String certification) {

    /** What was revoked. */
    public enum Kind {
        /** {@code target} is a governed group name. */
        GROUP,
        /** {@code target} is an absolute path holding a named user ACL entry. */
        DIRECT
    }

    public RevokedItem {
        Objects.requireNonNull(account, "account");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(reviewer, "reviewer");
        Objects.requireNonNull(certification, "certification");
    }
}
