package io.github.whatheheckisthis.fsgov.evidence;

import io.github.whatheheckisthis.fsgov.model.AccessContext;
import io.github.whatheheckisthis.fsgov.model.AccessDecision;
import io.github.whatheheckisthis.fsgov.model.AccessEvaluator;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Compares the access IdentityIQ says each account should hold with the
 * effective access the snapshot actually grants. The output feeds targeted
 * certifications (excess access becomes a review item) and closes the loop
 * after remediation (a revoked item must now be MATCH).
 */
public final class AccessDiffer {

    private final FilesystemSnapshot snapshot;
    private final AccessContext context;

    public AccessDiffer(FilesystemSnapshot snapshot, AccessContext context) {
        this.snapshot = snapshot;
        this.context = context;
    }

    public AccessDiffer(FilesystemSnapshot snapshot) {
        this(snapshot, AccessContext.LOCAL);
    }

    /**
     * Evaluates every account in scope against every path in scope. Pairs
     * where both desired and actual are empty are omitted.
     */
    public EvidenceBundle diff(String label, Collection<DesiredAccess> desired,
                               Collection<String> accounts, Collection<String> paths) {
        Map<String, PermissionSet> want = new HashMap<>();
        Set<String> accountScope = new TreeSet<>(accounts);
        Set<String> pathScope = new TreeSet<>(paths);
        for (DesiredAccess d : desired) {
            want.merge(key(d.account(), d.path()), d.permissions(), PermissionSet::union);
            accountScope.add(d.account());
            pathScope.add(d.path());
        }
        AccessEvaluator evaluator = new AccessEvaluator(snapshot);
        List<EvidenceRecord> records = new ArrayList<>();
        for (String account : accountScope) {
            for (String path : pathScope) {
                PermissionSet d = want.getOrDefault(key(account, path), PermissionSet.NONE);
                AccessDecision actual = evaluator.evaluate(account, path, context);
                PermissionSet a = actual.permissions();
                if (d.isEmpty() && a.isEmpty()) {
                    continue;
                }
                records.add(new EvidenceRecord(account, path, d, a, status(d, a), actual.source()));
            }
        }
        return new EvidenceBundle(label, records);
    }

    static EvidenceStatus status(PermissionSet desired, PermissionSet actual) {
        boolean excess = !actual.minus(desired).isEmpty();
        boolean missing = !desired.minus(actual).isEmpty();
        if (excess && missing) {
            return EvidenceStatus.DIVERGENT;
        }
        if (excess) {
            return EvidenceStatus.EXCESS;
        }
        return missing ? EvidenceStatus.MISSING : EvidenceStatus.MATCH;
    }

    private static String key(String account, String path) {
        return account + "\u0000" + path;
    }
}
