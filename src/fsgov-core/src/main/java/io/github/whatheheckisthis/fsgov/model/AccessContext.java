package io.github.whatheheckisthis.fsgov.model;

import java.util.Objects;

/**
 * Where an access check happens: on the file server itself, or on an NFSv3
 * client identified by the client specification it matches in
 * {@code /etc/exports}.
 */
public record AccessContext(String nfsClient) {

    public static final AccessContext LOCAL = new AccessContext(null);

    public static AccessContext nfs(String client) {
        return new AccessContext(Objects.requireNonNull(client, "client"));
    }

    public boolean isNfs() {
        return nfsClient != null;
    }
}
