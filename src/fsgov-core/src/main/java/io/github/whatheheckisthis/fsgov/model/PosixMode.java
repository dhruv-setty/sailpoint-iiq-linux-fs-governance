package io.github.whatheheckisthis.fsgov.model;

import java.util.Objects;

/**
 * Classic POSIX mode bits, including set-user-ID, set-group-ID and the sticky
 * bit. When an extended ACL is present the group class bits of the mode hold
 * the ACL mask, which is how the kernel and {@code ls -l} report them.
 */
public record PosixMode(int bits) {

    private static final int SETUID = 04000;
    private static final int SETGID = 02000;
    private static final int STICKY = 01000;

    public PosixMode {
        if (bits < 0 || bits > 07777) {
            throw new IllegalArgumentException("Mode out of range: " + Integer.toOctalString(bits));
        }
    }

    /**
     * Parses octal ({@code "2770"}, {@code "0755"}) or the nine or ten character
     * symbolic form printed by {@code ls -l} ({@code "drwxrws--T"}).
     */
    public static PosixMode parse(String text) {
        Objects.requireNonNull(text, "text");
        String t = text.trim();
        if (t.matches("[0-7]{3,4}")) {
            return new PosixMode(Integer.parseInt(t, 8));
        }
        if (t.length() == 10) {
            t = t.substring(1);
        }
        if (t.length() != 9) {
            throw new IllegalArgumentException("Unrecognised mode: '" + text + "'");
        }
        int bits = 0;
        bits |= symbolicTriplet(t.substring(0, 3), SETUID, 's') << 6;
        bits |= symbolicTriplet(t.substring(3, 6), SETGID, 's') << 3;
        bits |= symbolicTriplet(t.substring(6, 9), STICKY, 't');
        bits |= specialBit(t.charAt(2), SETUID, 's');
        bits |= specialBit(t.charAt(5), SETGID, 's');
        bits |= specialBit(t.charAt(8), STICKY, 't');
        return new PosixMode(bits);
    }

    private static int symbolicTriplet(String triplet, int special, char lower) {
        char x = triplet.charAt(2);
        boolean exec = x == 'x' || x == lower;
        boolean specialOnly = x == Character.toUpperCase(lower);
        if (!(exec || specialOnly || x == '-')) {
            throw new IllegalArgumentException("Unexpected character '" + x + "' in '" + triplet + "'");
        }
        return PermissionSet.parse(triplet.substring(0, 2) + (exec ? 'x' : '-')).toOctalDigit();
    }

    private static int specialBit(char c, int bit, char lower) {
        return (c == lower || c == Character.toUpperCase(lower)) ? bit : 0;
    }

    public static PosixMode of(PermissionSet owner, PermissionSet group, PermissionSet other) {
        return new PosixMode(owner.toOctalDigit() << 6 | group.toOctalDigit() << 3 | other.toOctalDigit());
    }

    public PermissionSet owner() {
        return PermissionSet.fromOctalDigit((bits >> 6) & 7);
    }

    public PermissionSet group() {
        return PermissionSet.fromOctalDigit((bits >> 3) & 7);
    }

    public PermissionSet other() {
        return PermissionSet.fromOctalDigit(bits & 7);
    }

    public boolean setuid() {
        return (bits & SETUID) != 0;
    }

    public boolean setgid() {
        return (bits & SETGID) != 0;
    }

    public boolean sticky() {
        return (bits & STICKY) != 0;
    }

    /** Returns a copy whose group class bits are replaced, as chmod does when a mask changes. */
    public PosixMode withGroup(PermissionSet group) {
        return new PosixMode((bits & ~070) | group.toOctalDigit() << 3);
    }

    public String toOctal() {
        return String.format("%04o", bits);
    }

    @Override
    public String toString() {
        return toOctal();
    }
}
