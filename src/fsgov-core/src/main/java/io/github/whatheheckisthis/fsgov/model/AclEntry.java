package io.github.whatheheckisthis.fsgov.model;

import java.util.Objects;

/**
 * One POSIX.1e ACL entry. A default entry applies to objects created inside a
 * directory and has no effect on access checks for the directory itself.
 */
public record AclEntry(AclTag tag, String qualifier, PermissionSet permissions, boolean defaultScope) {

    public AclEntry {
        Objects.requireNonNull(tag, "tag");
        Objects.requireNonNull(permissions, "permissions");
        if (tag.isNamed()) {
            if (qualifier == null || qualifier.isBlank()) {
                throw new IllegalArgumentException(tag + " entry requires a qualifier");
            }
        } else if (qualifier != null && !qualifier.isEmpty()) {
            throw new IllegalArgumentException(tag + " entry must not carry a qualifier");
        } else {
            qualifier = "";
        }
    }

    public static AclEntry access(AclTag tag, String qualifier, PermissionSet permissions) {
        return new AclEntry(tag, qualifier, permissions, false);
    }

    public static AclEntry defaults(AclTag tag, String qualifier, PermissionSet permissions) {
        return new AclEntry(tag, qualifier, permissions, true);
    }

    /** Parses a single getfacl line such as {@code "default:group:fs_fin_rw:rwx"}. */
    public static AclEntry parse(String line) {
        String text = line.trim();
        int comment = text.indexOf('#');
        if (comment >= 0) {
            text = text.substring(0, comment).trim();
        }
        boolean def = false;
        if (text.startsWith("default:")) {
            def = true;
            text = text.substring("default:".length());
        } else if (text.startsWith("d:")) {
            def = true;
            text = text.substring(2);
        }
        String[] parts = text.split(":", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("Malformed ACL entry: '" + line + "'");
        }
        String qualifier = parts[1];
        AclTag tag = AclTag.of(parts[0], !qualifier.isEmpty());
        return new AclEntry(tag, tag.isNamed() ? qualifier : null, PermissionSet.parse(parts[2]), def);
    }

    /** True when the other entry addresses the same tag, qualifier and scope. */
    public boolean sameSlot(AclEntry other) {
        return tag == other.tag && qualifier.equals(other.qualifier) && defaultScope == other.defaultScope;
    }

    public AclEntry withPermissions(PermissionSet p) {
        return new AclEntry(tag, tag.isNamed() ? qualifier : null, p, defaultScope);
    }

    /** The getfacl and setfacl text form. */
    public String toText() {
        return (defaultScope ? "default:" : "") + tag.keyword() + ":" + qualifier + ":" + permissions;
    }

    @Override
    public String toString() {
        return toText();
    }
}
