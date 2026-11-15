package io.github.whatheheckisthis.fsgov.model;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** One exported directory and its client rules. */
public record NfsExport(String path, List<NfsClientRule> clients) {

    public NfsExport {
        Objects.requireNonNull(path, "path");
        clients = List.copyOf(clients);
    }

    /** True when the path is the export root or below it. */
    public boolean covers(String candidate) {
        return candidate.equals(path) || candidate.startsWith(path.endsWith("/") ? path : path + "/");
    }

    /** First rule whose client spec equals the given spec, as exportfs matches literal specs. */
    public Optional<NfsClientRule> ruleFor(String client) {
        return clients.stream().filter(c -> c.client().equals(client)).findFirst();
    }
}
