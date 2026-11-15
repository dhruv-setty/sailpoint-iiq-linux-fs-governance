package io.github.whatheheckisthis.fsgov.model;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * One client specification in an {@code /etc/exports} line with its options,
 * for example {@code 10.20.0.0/16(rw,sync,root_squash)}.
 */
public record NfsClientRule(String client, List<String> options) {

    public static final int DEFAULT_ANON_ID = 65534;

    public NfsClientRule {
        Objects.requireNonNull(client, "client");
        options = List.copyOf(options);
    }

    /** Exports are read-only unless {@code rw} is given; the last of rw and ro wins. */
    public boolean readWrite() {
        int rw = options.lastIndexOf("rw");
        int ro = options.lastIndexOf("ro");
        return rw > ro;
    }

    /** root_squash is the default; only no_root_squash disables it. */
    public boolean rootSquash() {
        return options.lastIndexOf("root_squash") >= options.lastIndexOf("no_root_squash");
    }

    public boolean allSquash() {
        return options.lastIndexOf("all_squash") > options.lastIndexOf("no_all_squash");
    }

    public int anonUid() {
        return numericOption("anonuid").orElse(DEFAULT_ANON_ID);
    }

    public int anonGid() {
        return numericOption("anongid").orElse(DEFAULT_ANON_ID);
    }

    /** The security flavour list; AUTH_SYS ({@code sys}) when absent. */
    public String security() {
        return options.stream().filter(o -> o.startsWith("sec=")).map(o -> o.substring(4))
                .reduce((a, b) -> b).orElse("sys");
    }

    private Optional<Integer> numericOption(String key) {
        return options.stream()
                .filter(o -> o.startsWith(key + "="))
                .map(o -> Integer.parseInt(o.substring(key.length() + 1)))
                .reduce((a, b) -> b);
    }
}
