package io.github.whatheheckisthis.fsgov.evidence;

import io.github.whatheheckisthis.fsgov.model.PermissionSet;

/** Evidence that one revoked item was, or was not, removed. */
public record RemediationRecord(RevokedItem item, PermissionSet before, PermissionSet after,
                                RemediationOutcome outcome, String detail) {

    public String canonical() {
        return String.join("\t", item.certification(), item.reviewer(), item.account(), item.kind().name(),
                item.target(), before.toString(), after.toString(), outcome.name(), detail);
    }
}
