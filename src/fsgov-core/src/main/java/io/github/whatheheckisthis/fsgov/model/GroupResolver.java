package io.github.whatheheckisthis.fsgov.model;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Flattens group nesting into the supplementary group list the kernel would
 * see once a directory service has resolved it. Cycles are tolerated and
 * reported, because legacy directories frequently contain them.
 */
public final class GroupResolver {

    private final FilesystemSnapshot snapshot;

    public GroupResolver(FilesystemSnapshot snapshot) {
        this.snapshot = snapshot;
    }

    /**
     * All groups the account belongs to: its primary group, its direct
     * memberships, and every group that contains one of those as a nested
     * member, transitively.
     */
    public Set<String> effectiveGroups(String accountName) {
        Set<String> result = new TreeSet<>();
        Deque<String> work = new ArrayDeque<>(snapshot.directGroupsOf(accountName));
        snapshot.account(accountName)
                .flatMap(a -> snapshot.groupByGid(a.primaryGid()))
                .ifPresent(g -> work.add(g.name()));
        while (!work.isEmpty()) {
            String current = work.pop();
            if (result.add(current)) {
                for (Group parent : snapshot.groups().values()) {
                    if (parent.nestedGroups().contains(current)) {
                        work.push(parent.name());
                    }
                }
            }
        }
        return result;
    }

    /** Effective gids for the account, used for access evaluation. */
    public Set<Integer> effectiveGids(String accountName) {
        Set<Integer> gids = new TreeSet<>();
        for (String name : effectiveGroups(accountName)) {
            snapshot.group(name).ifPresent(g -> gids.add(g.gid()));
        }
        snapshot.account(accountName).ifPresent(a -> gids.add(a.primaryGid()));
        return gids;
    }

    /**
     * Accounts that hold the group directly or through nesting. Used for
     * empty group detection and to explain residual access after a revoke.
     */
    public Set<String> effectiveMembers(String groupName) {
        Set<String> members = new TreeSet<>();
        Set<String> visited = new LinkedHashSet<>();
        Deque<String> work = new ArrayDeque<>(List.of(groupName));
        while (!work.isEmpty()) {
            String g = work.pop();
            if (!visited.add(g)) {
                continue;
            }
            snapshot.group(g).ifPresent(group -> {
                members.addAll(group.members());
                work.addAll(group.nestedGroups());
                for (Account a : snapshot.accounts().values()) {
                    if (a.primaryGid() == group.gid()) {
                        members.add(a.name());
                    }
                }
            });
        }
        return members;
    }

    /**
     * Groups other than {@code excluded} through which the account still
     * reaches {@code target}: the nested paths that survive removal of one
     * direct membership.
     */
    public Set<String> alternatePathsTo(String accountName, String target, String excluded) {
        Set<String> via = new TreeSet<>();
        for (String direct : snapshot.directGroupsOf(accountName)) {
            if (direct.equals(excluded)) {
                continue;
            }
            if (reaches(direct, target, new LinkedHashSet<>())) {
                via.add(direct);
            }
        }
        return via;
    }

    private boolean reaches(String from, String target, Set<String> visited) {
        if (from.equals(target)) {
            return true;
        }
        if (!visited.add(from)) {
            return false;
        }
        for (Group parent : snapshot.groups().values()) {
            if (parent.nestedGroups().contains(from) && reaches(parent.name(), target, visited)) {
                return true;
            }
        }
        return false;
    }

    /** Groups that participate in a nesting cycle. */
    public Set<String> cycles() {
        Set<String> cyclic = new TreeSet<>();
        for (Group g : snapshot.groups().values()) {
            for (Group parent : snapshot.groups().values()) {
                if (parent.nestedGroups().contains(g.name())
                        && reaches(parent.name(), g.name(), new LinkedHashSet<>())) {
                    cyclic.add(g.name());
                }
            }
        }
        return cyclic;
    }
}
