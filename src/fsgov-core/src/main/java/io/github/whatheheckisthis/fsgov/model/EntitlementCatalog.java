package io.github.whatheheckisthis.fsgov.model;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * The governed entitlements for one application, keyed by group name. In
 * IdentityIQ this corresponds to the entitlement catalog (ManagedAttribute
 * objects) for the {@code groups} attribute of the file system application.
 */
public final class EntitlementCatalog {

    private final Map<String, ShareEntitlement> byGroup;

    public EntitlementCatalog(Collection<ShareEntitlement> entitlements) {
        Map<String, ShareEntitlement> m = new TreeMap<>();
        for (ShareEntitlement e : entitlements) {
            if (m.put(e.group(), e) != null) {
                throw new IllegalArgumentException("Duplicate entitlement for group " + e.group());
            }
        }
        this.byGroup = Collections.unmodifiableMap(m);
    }

    public static EntitlementCatalog of(ShareEntitlement... entitlements) {
        return new EntitlementCatalog(List.of(entitlements));
    }

    public Optional<ShareEntitlement> forGroup(String group) {
        return Optional.ofNullable(byGroup.get(group));
    }

    public Collection<ShareEntitlement> all() {
        return byGroup.values();
    }

    /** True when the path is a governed share root or lies below one. */
    public boolean governs(String path) {
        return byGroup.values().stream()
                .anyMatch(e -> path.equals(e.path()) || path.startsWith(e.path() + "/"));
    }
}
