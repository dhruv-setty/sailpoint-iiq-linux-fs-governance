package io.github.whatheheckisthis.fsgov.plan;

import io.github.whatheheckisthis.fsgov.model.PermissionSet;

import java.util.Objects;

/**
 * A single attribute request against one account, the shape of an
 * IdentityIQ {@code AttributeRequest} inside an {@code AccountRequest}.
 *
 * <ul>
 *   <li>{@value #ATTR_GROUPS}: value is a group name from the entitlement catalog.</li>
 *   <li>{@value #ATTR_DIRECT_PERMISSIONS}: value is {@code <absolute path>:<rwx>}, a direct
 *       named user ACL entry. Used for exceptions only; group grants are preferred.</li>
 * </ul>
 */
public record ProvisioningRequest(String account, Operation operation, String attribute, String value) {

    public static final String ATTR_GROUPS = "groups";
    public static final String ATTR_DIRECT_PERMISSIONS = "directPermissions";

    public ProvisioningRequest {
        Objects.requireNonNull(account, "account");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(attribute, "attribute");
        Objects.requireNonNull(value, "value");
        if (!ATTR_GROUPS.equals(attribute) && !ATTR_DIRECT_PERMISSIONS.equals(attribute)) {
            throw new IllegalArgumentException("Unsupported attribute: " + attribute);
        }
    }

    public static ProvisioningRequest addGroup(String account, String group) {
        return new ProvisioningRequest(account, Operation.ADD, ATTR_GROUPS, group);
    }

    public static ProvisioningRequest removeGroup(String account, String group) {
        return new ProvisioningRequest(account, Operation.REMOVE, ATTR_GROUPS, group);
    }

    public static ProvisioningRequest addDirect(String account, String path, PermissionSet perms) {
        return new ProvisioningRequest(account, Operation.ADD, ATTR_DIRECT_PERMISSIONS, path + ":" + perms);
    }

    public static ProvisioningRequest removeDirect(String account, String path) {
        return new ProvisioningRequest(account, Operation.REMOVE, ATTR_DIRECT_PERMISSIONS, path + ":---");
    }

    /** Path part of a direct permission value. */
    public String directPath() {
        int i = value.lastIndexOf(':');
        if (i <= 0) {
            throw new IllegalArgumentException("Direct permission value must be <path>:<rwx>: " + value);
        }
        return value.substring(0, i);
    }

    /** Permission part of a direct permission value. */
    public PermissionSet directPermissions() {
        return PermissionSet.parse(value.substring(value.lastIndexOf(':') + 1));
    }
}
