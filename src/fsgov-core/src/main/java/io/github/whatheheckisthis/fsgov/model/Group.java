package io.github.whatheheckisthis.fsgov.model;

import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * A POSIX group with direct members. {@code nestedGroups} records group
 * nesting held in a directory service (for example LDAP groups resolved by
 * SSSD). Flat {@code /etc/group} files cannot express nesting, so on such
 * hosts this set is empty and the kernel never sees it.
 */
public record Group(String name, int gid, Set<String> members, Set<String> nestedGroups) {

    public Group {
        Objects.requireNonNull(name, "name");
        members = Set.copyOf(new TreeSet<>(members == null ? Set.of() : members));
        nestedGroups = Set.copyOf(new TreeSet<>(nestedGroups == null ? Set.of() : nestedGroups));
    }

    public static Group of(String name, int gid, String... members) {
        return new Group(name, gid, Set.of(members), Set.of());
    }

    public Group withMember(String account) {
        Set<String> m = new TreeSet<>(members);
        m.add(account);
        return new Group(name, gid, m, nestedGroups);
    }

    public Group withoutMember(String account) {
        Set<String> m = new TreeSet<>(members);
        m.remove(account);
        return new Group(name, gid, m, nestedGroups);
    }

    public Group withNested(String group) {
        Set<String> n = new TreeSet<>(nestedGroups);
        n.add(group);
        return new Group(name, gid, members, n);
    }
}
