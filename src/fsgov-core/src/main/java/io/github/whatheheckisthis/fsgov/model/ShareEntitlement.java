package io.github.whatheheckisthis.fsgov.model;

import java.util.Objects;

/**
 * A governed entitlement: membership of {@code group} grants
 * {@code permissions} on {@code path}. The binding is held as a named group
 * ACL entry, and as a default entry too when {@code inherit} is set, so new
 * content below a directory carries the same grant.
 */
public record ShareEntitlement(String group, int gid, String path, PermissionSet permissions,
                               boolean inherit, String businessOwner) {

    public ShareEntitlement {
        Objects.requireNonNull(group, "group");
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(permissions, "permissions");
    }

    /** True for entitlements that allow modification of content. */
    public boolean isWrite() {
        return permissions.write();
    }
}
