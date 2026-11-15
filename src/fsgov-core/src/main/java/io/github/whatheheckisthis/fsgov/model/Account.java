package io.github.whatheheckisthis.fsgov.model;

import java.util.Objects;

/** A local or directory-backed POSIX account as the target host resolves it. */
public record Account(String name, int uid, int primaryGid) {

    public static final int ROOT_UID = 0;

    public Account {
        Objects.requireNonNull(name, "name");
        if (uid < 0 || primaryGid < 0) {
            throw new IllegalArgumentException("uid and gid must be non-negative");
        }
    }

    public boolean isRoot() {
        return uid == ROOT_UID;
    }
}
