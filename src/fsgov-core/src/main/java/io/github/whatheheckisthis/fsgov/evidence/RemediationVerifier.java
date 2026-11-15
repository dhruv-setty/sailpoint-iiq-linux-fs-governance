package io.github.whatheheckisthis.fsgov.evidence;

import io.github.whatheheckisthis.fsgov.model.AccessContext;
import io.github.whatheheckisthis.fsgov.model.AccessEvaluator;
import io.github.whatheheckisthis.fsgov.model.AclTag;
import io.github.whatheheckisthis.fsgov.model.EntitlementCatalog;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;
import io.github.whatheheckisthis.fsgov.model.ShareEntitlement;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Closes the certification revocation loop: compares the state captured when
 * the campaign was generated with the state aggregated after remediation, and
 * records for each revoked item whether the access is gone.
 */
public final class RemediationVerifier {

    private final EntitlementCatalog catalog;

    public RemediationVerifier(EntitlementCatalog catalog) {
        this.catalog = catalog;
    }

    public RemediationReport verify(String certification, String planDigest, FilesystemSnapshot before,
                                    FilesystemSnapshot after, List<RevokedItem> items) {
        AccessEvaluator was = new AccessEvaluator(before);
        AccessEvaluator now = new AccessEvaluator(after);
        List<RemediationRecord> records = new ArrayList<>();
        for (RevokedItem item : items) {
            String path = pathOf(item);
            if (path == null) {
                records.add(new RemediationRecord(item, PermissionSet.NONE, PermissionSet.NONE,
                        RemediationOutcome.INCONCLUSIVE, "group is not in the entitlement catalog"));
                continue;
            }
            PermissionSet b = was.evaluate(item.account(), path, AccessContext.LOCAL).permissions();
            PermissionSet a = now.evaluate(item.account(), path, AccessContext.LOCAL).permissions();
            boolean stillThere;
            if (item.kind() == RevokedItem.Kind.GROUP) {
                stillThere = after.group(item.target()).map(g -> g.members().contains(item.account())).orElse(false);
            } else {
                stillThere = after.path(path).map(p -> p.acl().find(AclTag.USER, item.account(), false).isPresent())
                        .orElse(false);
            }
            records.add(new RemediationRecord(item, b, a,
                    stillThere ? RemediationOutcome.NOT_REMOVED : RemediationOutcome.VERIFIED,
                    stillThere ? "revoked access still present" : "revoked access removed"));
        }
        return new RemediationReport(certification, planDigest, records);
    }

    private String pathOf(RevokedItem item) {
        if (item.kind() == RevokedItem.Kind.DIRECT) {
            return item.target();
        }
        Optional<ShareEntitlement> e = catalog.forGroup(item.target());
        return e.map(ShareEntitlement::path).orElse(null);
    }
}
