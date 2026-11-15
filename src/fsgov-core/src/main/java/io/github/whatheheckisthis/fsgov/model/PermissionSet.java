package io.github.whatheheckisthis.fsgov.model;

import java.util.Objects;

/**
 * The three POSIX permission bits (read, write, execute or search) for one
 * permission class or one ACL entry. Immutable.
 */
public record PermissionSet(boolean read, boolean write, boolean execute) {

    public static final PermissionSet NONE = new PermissionSet(false, false, false);
    public static final PermissionSet READ_ONLY = new PermissionSet(true, false, false);
    public static final PermissionSet READ_EXECUTE = new PermissionSet(true, false, true);
    public static final PermissionSet READ_WRITE = new PermissionSet(true, true, false);
    public static final PermissionSet ALL = new PermissionSet(true, true, true);

    /** Parses the getfacl or ls form, for example {@code "r-x"}. */
    public static PermissionSet parse(String text) {
        Objects.requireNonNull(text, "text");
        if (text.length() != 3) {
            throw new IllegalArgumentException("Permission text must be three characters: '" + text + "'");
        }
        return new PermissionSet(
                flag(text.charAt(0), 'r', text),
                flag(text.charAt(1), 'w', text),
                flag(text.charAt(2), 'x', text));
    }

    /** Builds a set from a single octal digit, 0 to 7. */
    public static PermissionSet fromOctalDigit(int digit) {
        if (digit < 0 || digit > 7) {
            throw new IllegalArgumentException("Octal digit out of range: " + digit);
        }
        return new PermissionSet((digit & 4) != 0, (digit & 2) != 0, (digit & 1) != 0);
    }

    private static boolean flag(char c, char expected, String text) {
        if (c == expected) {
            return true;
        }
        if (c == '-') {
            return false;
        }
        throw new IllegalArgumentException("Unexpected permission character '" + c + "' in '" + text + "'");
    }

    public int toOctalDigit() {
        return (read ? 4 : 0) | (write ? 2 : 0) | (execute ? 1 : 0);
    }

    public PermissionSet union(PermissionSet other) {
        return new PermissionSet(read || other.read, write || other.write, execute || other.execute);
    }

    public PermissionSet intersect(PermissionSet other) {
        return new PermissionSet(read && other.read, write && other.write, execute && other.execute);
    }

    /** Bits present in this set and absent from {@code other}. */
    public PermissionSet minus(PermissionSet other) {
        return new PermissionSet(read && !other.read, write && !other.write, execute && !other.execute);
    }

    /** True when every bit in {@code other} is also set here. */
    public boolean containsAll(PermissionSet other) {
        return other.minus(this).isEmpty();
    }

    public boolean isEmpty() {
        return !read && !write && !execute;
    }

    @Override
    public String toString() {
        return (read ? "r" : "-") + (write ? "w" : "-") + (execute ? "x" : "-");
    }
}
