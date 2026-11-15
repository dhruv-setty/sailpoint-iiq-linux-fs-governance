package io.github.whatheheckisthis.fsgov.plan;

import io.github.whatheheckisthis.fsgov.evidence.RevokedItem;
import io.github.whatheheckisthis.fsgov.model.EntitlementCatalog;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;

import java.util.ArrayList;
import java.util.List;

/**
 * Turns the revoked items of a certification into change plans for the
 * connector, one plan per item, so each revocation can be tracked and
 * retried on its own.
 */
public final class RevocationPlanner {

    private final ChangePlanner planner;

    public RevocationPlanner(EntitlementCatalog catalog) {
        this.planner = new ChangePlanner(catalog);
    }

    public List<ChangePlan> plan(FilesystemSnapshot snapshot, List<RevokedItem> items) {
        List<ChangePlan> plans = new ArrayList<>();
        for (RevokedItem item : items) {
            ProvisioningRequest request = item.kind() == RevokedItem.Kind.GROUP
                    ? ProvisioningRequest.removeGroup(item.account(), item.target())
                    : ProvisioningRequest.removeDirect(item.account(), item.target());
            plans.add(planner.plan(snapshot, List.of(request)));
        }
        return plans;
    }
}
