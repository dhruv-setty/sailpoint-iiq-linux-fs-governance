package io.github.whatheheckisthis.fsgov.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * An immutable POSIX.1e access control list, holding both access and default
 * entries. Entries are kept in the canonical order getfacl prints.
 */
public final class Acl {

    private static final Comparator<AclEntry> CANONICAL = Comparator
            .comparing(AclEntry::defaultScope)
            .thenComparing(AclEntry::tag)
            .thenComparing(AclEntry::qualifier);

    private final List<AclEntry> entries;

    private Acl(List<AclEntry> entries) {
        List<AclEntry> sorted = new ArrayList<>(entries);
        sorted.sort(CANONICAL);
        this.entries = Collections.unmodifiableList(sorted);
    }

    public static Acl of(List<AclEntry> entries) {
        List<AclEntry> deduped = new ArrayList<>();
        for (AclEntry e : entries) {
            deduped.removeIf(existing -> existing.sameSlot(e));
            deduped.add(e);
        }
        return new Acl(deduped);
    }

    /** The minimal ACL equivalent to a mode: three entries, no mask. */
    public static Acl fromMode(PosixMode mode) {
        return new Acl(List.of(
                AclEntry.access(AclTag.USER_OBJ, null, mode.owner()),
                AclEntry.access(AclTag.GROUP_OBJ, null, mode.group()),
                AclEntry.access(AclTag.OTHER, null, mode.other())));
    }

    public List<AclEntry> entries() {
        return entries;
    }

    public List<AclEntry> accessEntries() {
        return entries.stream().filter(e -> !e.defaultScope()).toList();
    }

    public List<AclEntry> defaultEntries() {
        return entries.stream().filter(AclEntry::defaultScope).toList();
    }

    public Optional<AclEntry> find(AclTag tag, String qualifier, boolean defaultScope) {
        String q = qualifier == null ? "" : qualifier;
        return entries.stream()
                .filter(e -> e.tag() == tag && e.qualifier().equals(q) && e.defaultScope() == defaultScope)
                .findFirst();
    }

    /** Adds the entry, replacing any entry in the same slot, as {@code setfacl -m} does. */
    public Acl with(AclEntry entry) {
        List<AclEntry> copy = new ArrayList<>(entries);
        copy.removeIf(e -> e.sameSlot(entry));
        copy.add(entry);
        return new Acl(copy);
    }

    /** Removes the entry in the given slot, as {@code setfacl -x} does. */
    public Acl without(AclTag tag, String qualifier, boolean defaultScope) {
        String q = qualifier == null ? "" : qualifier;
        List<AclEntry> copy = new ArrayList<>(entries);
        copy.removeIf(e -> e.tag() == tag && e.qualifier().equals(q) && e.defaultScope() == defaultScope);
        return new Acl(copy);
    }

    /** True when the scope holds named entries, which require a mask. */
    public boolean hasNamedEntries(boolean defaultScope) {
        return entries.stream().anyMatch(e -> e.defaultScope() == defaultScope && e.tag().isNamed());
    }

    /**
     * The union of every group class entry in the scope. This is the mask that
     * {@code setfacl} computes when it is not told otherwise.
     */
    public PermissionSet computedMask(boolean defaultScope) {
        PermissionSet mask = PermissionSet.NONE;
        for (AclEntry e : entries) {
            if (e.defaultScope() == defaultScope && e.tag().isMaskedClass()) {
                mask = mask.union(e.permissions());
            }
        }
        return mask;
    }

    /** The mask entry if present, otherwise the group owner entry, as the kernel treats a minimal ACL. */
    public PermissionSet effectiveMask() {
        return find(AclTag.MASK, null, false)
                .or(() -> find(AclTag.GROUP_OBJ, null, false))
                .map(AclEntry::permissions)
                .orElse(PermissionSet.NONE);
    }

    public boolean isMinimal() {
        return entries.stream().noneMatch(e -> e.defaultScope() || e.tag().isNamed() || e.tag() == AclTag.MASK);
    }

    /** Text in getfacl order, one entry per line. */
    public String toText() {
        StringBuilder sb = new StringBuilder();
        for (AclEntry e : entries) {
            sb.append(e.toText()).append('\n');
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Acl other && entries.equals(other.entries);
    }

    @Override
    public int hashCode() {
        return entries.hashCode();
    }

    @Override
    public String toString() {
        return entries.toString();
    }
}
