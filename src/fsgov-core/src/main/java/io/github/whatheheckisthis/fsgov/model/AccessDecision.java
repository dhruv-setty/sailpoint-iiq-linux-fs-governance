package io.github.whatheheckisthis.fsgov.model;

/**
 * Effective rights of one principal on one path and the ACL entry or rule
 * that produced them, recorded so certification evidence can explain itself.
 */
public record AccessDecision(PermissionSet permissions, String source) {

    public static AccessDecision none(String reason) {
        return new AccessDecision(PermissionSet.NONE, reason);
    }
}
