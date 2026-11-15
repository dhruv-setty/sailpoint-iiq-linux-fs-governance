package io.github.whatheheckisthis.fsgov.evidence;

import io.github.whatheheckisthis.fsgov.model.AccessContext;
import io.github.whatheheckisthis.fsgov.model.AccessDecision;
import io.github.whatheheckisthis.fsgov.model.AccessEvaluator;
import io.github.whatheheckisthis.fsgov.model.AclTag;
import io.github.whatheheckisthis.fsgov.model.EntitlementCatalog;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.GroupResolver;
import io.github.whatheheckisthis.fsgov.model.PathEntry;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;
import io.github.whatheheckisthis.fsgov.model.ShareEntitlement;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Closes the certification revocation loop: compares the state captured when
 * the campaign was generated with the state aggregated after remediation, and
 * records for each revoked item whether the access is gone.
 *
 * <p>Group revocations are judged on effective membership, so access that
 * survives through a nested group is reported as {@code NOT_REMOVED}. Missing
 * data (path or account absent from the after snapshot) is reported as
 * {@code INCONCLUSIVE}, never as removed.</p>
 */
public final class RemediationVerifier {

    private final EntitlementCatalog catalog;

    public RemediationVerifier(EntitlementCatalog catalog) {
        this.catalog = catalog;
    }

    /**
     * @param capturedAt aggregation time of {@code after}; supplied by the caller so
     *                   the report digest is reproducible from the same inputs
     */
    public RemediationReport verify(String certification, String planDigest, Instant capturedAt,
                                    FilesystemSnapshot before, FilesystemSnapshot after, List<RevokedItem> items) {
        AccessEvaluator was = new AccessEvaluator(before);
        AccessEvaluator now = new AccessEvaluator(after);
        GroupResolver resolver = new GroupResolver(after);
        List<RemediationRecord> records = new ArrayList<>();
        for (RevokedItem item : items) {
            String path = pathOf(item);
            if (path == null) {
                records.add(inconclusive(item, "group is not in the entitlement catalog"));
                continue;
            }
            Optional<PathEntry> afterPath = after.path(path);
            if (afterPath.isEmpty()) {
                records.add(inconclusive(item, path + " is not in the after snapshot"));
                continue;
            }
            if (after.account(item.account()).isEmpty()) {
                records.add(inconclusive(item, "account is not in the after snapshot"));
                continue;
            }
            PermissionSet b = was.evaluate(item.account(), path, AccessContext.LOCAL).permissions();
            AccessDecision a = now.evaluate(item.account(), path, AccessContext.LOCAL);
            String residual = item.kind() == RevokedItem.Kind.GROUP
                    ? residualGroup(after, resolver, item)
                    : residualDirect(afterPath.get(), item);
            records.add(residual == null
                    ? new RemediationRecord(item, b, a.permissions(), RemediationOutcome.VERIFIED,
                            "revoked access removed; effective access from " + a.source())
                    : new RemediationRecord(item, b, a.permissions(), RemediationOutcome.NOT_REMOVED, residual));
        }
        return new RemediationReport(certification, planDigest, capturedAt, records);
    }

    private static String residualGroup(FilesystemSnapshot after, GroupResolver resolver, RevokedItem item) {
        boolean direct = after.group(item.target()).map(g -> g.members().contains(item.account())).orElse(false);
        if (direct) {
            return "still a direct member of " + item.target();
        }
        if (resolver.effectiveGroups(item.account()).contains(item.target())) {
            Set<String> via = resolver.alternatePathsTo(item.account(), item.target(), item.target());
            return "still reaches " + item.target() + " through nested group(s) " + via;
        }
        return null;
    }

    private static String residualDirect(PathEntry p, RevokedItem item) {
        boolean access = p.acl().find(AclTag.USER, item.account(), false).isPresent();
        boolean inherit = p.acl().find(AclTag.USER, item.account(), true).isPresent();
        if (access || inherit) {
            return "named user entry still present" + (access ? " (access)" : "") + (inherit ? " (default)" : "");
        }
        return null;
    }

    private static RemediationRecord inconclusive(RevokedItem item, String detail) {
        return new RemediationRecord(item, PermissionSet.NONE, PermissionSet.NONE, RemediationOutcome.INCONCLUSIVE, detail);
    }

    private String pathOf(RevokedItem item) {
        if (item.kind() == RevokedItem.Kind.DIRECT) {
            return item.target();
        }
        return catalog.forGroup(item.target()).map(ShareEntitlement::path).orElse(null);
    }
}
