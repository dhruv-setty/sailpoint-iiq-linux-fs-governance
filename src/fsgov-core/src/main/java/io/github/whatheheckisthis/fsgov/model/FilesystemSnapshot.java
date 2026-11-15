package io.github.whatheheckisthis.fsgov.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * An immutable view of one target host: accounts, groups, governed paths and
 * NFS exports. Snapshots are produced by aggregation (actual state) or by
 * applying a change plan to another snapshot (predicted state).
 */
public final class FilesystemSnapshot {

    private final Map<String, Account> accounts;
    private final Map<String, Group> groups;
    private final Map<String, PathEntry> paths;
    private final List<NfsExport> exports;

    private FilesystemSnapshot(Builder b) {
        this.accounts = Collections.unmodifiableMap(new TreeMap<>(b.accounts));
        this.groups = Collections.unmodifiableMap(new TreeMap<>(b.groups));
        this.paths = Collections.unmodifiableMap(new TreeMap<>(b.paths));
        this.exports = List.copyOf(b.exports);
    }

    public static Builder builder() {
        return new Builder();
    }

    public Builder toBuilder() {
        Builder b = new Builder();
        b.accounts.putAll(accounts);
        b.groups.putAll(groups);
        b.paths.putAll(paths);
        b.exports.addAll(exports);
        return b;
    }

    public Map<String, Account> accounts() {
        return accounts;
    }

    public Map<String, Group> groups() {
        return groups;
    }

    public Map<String, PathEntry> paths() {
        return paths;
    }

    public List<NfsExport> exports() {
        return exports;
    }

    public Optional<Account> account(String name) {
        return Optional.ofNullable(accounts.get(name));
    }

    public Optional<Account> accountByUid(int uid) {
        return accounts.values().stream().filter(a -> a.uid() == uid).findFirst();
    }

    public Optional<Group> group(String name) {
        return Optional.ofNullable(groups.get(name));
    }

    public Optional<Group> groupByGid(int gid) {
        return groups.values().stream().filter(g -> g.gid() == gid).findFirst();
    }

    public Optional<PathEntry> path(String path) {
        return Optional.ofNullable(paths.get(path));
    }

    /** The export that covers a path, choosing the longest export root. */
    public Optional<NfsExport> exportFor(String path) {
        return exports.stream().filter(e -> e.covers(path))
                .max((a, b) -> Integer.compare(a.path().length(), b.path().length()));
    }

    /**
     * Groups whose direct member list contains the account. Excludes the
     * primary group unless it is also listed, matching {@code /etc/group}.
     */
    public Set<String> directGroupsOf(String account) {
        Set<String> result = new LinkedHashSet<>();
        for (Group g : groups.values()) {
            if (g.members().contains(account)) {
                result.add(g.name());
            }
        }
        return result;
    }

    /** Mutable builder. */
    public static final class Builder {
        private final Map<String, Account> accounts = new TreeMap<>();
        private final Map<String, Group> groups = new TreeMap<>();
        private final Map<String, PathEntry> paths = new TreeMap<>();
        private final List<NfsExport> exports = new ArrayList<>();

        public Builder account(Account a) {
            accounts.put(a.name(), a);
            return this;
        }

        public Builder group(Group g) {
            groups.put(g.name(), g);
            return this;
        }

        public Builder path(PathEntry p) {
            paths.put(p.path(), p);
            return this;
        }

        public Builder export(NfsExport e) {
            exports.removeIf(x -> x.path().equals(e.path()));
            exports.add(e);
            return this;
        }

        public FilesystemSnapshot build() {
            return new FilesystemSnapshot(this);
        }
    }
}
