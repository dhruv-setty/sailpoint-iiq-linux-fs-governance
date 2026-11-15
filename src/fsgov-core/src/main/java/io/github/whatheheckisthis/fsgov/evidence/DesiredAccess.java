package io.github.whatheheckisthis.fsgov.evidence;

import io.github.whatheheckisthis.fsgov.model.PermissionSet;

import java.util.Objects;

/** Access an account should hold on a path, as IdentityIQ's identity model asserts it. */
public record DesiredAccess(String account, String path, PermissionSet permissions) {

    public DesiredAccess {
        Objects.requireNonNull(account, "account");
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(permissions, "permissions");
    }
}
