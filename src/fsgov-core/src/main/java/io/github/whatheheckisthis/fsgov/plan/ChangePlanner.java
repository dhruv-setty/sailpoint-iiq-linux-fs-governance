package io.github.whatheheckisthis.fsgov.plan;

import io.github.whatheheckisthis.fsgov.model.Acl;
import io.github.whatheheckisthis.fsgov.model.AclEntry;
import io.github.whatheheckisthis.fsgov.model.AclTag;
import io.github.whatheheckisthis.fsgov.model.EntitlementCatalog;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.Group;
import io.github.whatheheckisthis.fsgov.model.GroupResolver;
import io.github.whatheheckisthis.fsgov.model.PathEntry;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;
import io.github.whatheheckisthis.fsgov.model.ShareEntitlement;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Turns IdentityIQ style attribute requests into an ordered, idempotent
 * {@link ChangePlan} against a snapshot of the target.
 *
 * <p>Properties the planner guarantees:</p>
 * <ul>
 *   <li>Idempotent: a request already satisfied by the snapshot yields no step,
 *       and planning again against the result of applying a plan yields an
 *       empty plan.</li>
 *   <li>Ordered: steps follow {@link Phase}, revocations first, and are
 *       sorted within a phase so the same input always yields the same plan.</li>
 *   <li>Conservative: when one plan both grants and revokes the same access,
 *       the revocation wins and a warning is raised.</li>
 *   <li>Explicit masks: the ACL mask is computed and written as its own step,
 *       never left to setfacl recalculation on the host.</li>
 * </ul>
 */
public final class ChangePlanner {

    private static final Comparator<ChangeStep> ORDER = Comparator
            .comparing(ChangeStep::phase)
            .thenComparing(ChangeStep::sortKey);

    private final EntitlementCatalog catalog;

    public ChangePlanner(EntitlementCatalog catalog) {
        this.catalog = catalog;
    }

    public ChangePlan plan(FilesystemSnapshot snapshot, List<ProvisioningRequest> requests) {
        Context ctx = new Context(snapshot);
        for (ProvisioningRequest r : revokeWins(ctx, requests)) {
            if (snapshot.account(r.account()).isEmpty()) {
                ctx.warn(PlanWarning.Code.ACCOUNT_NOT_FOUND, r.account(), "account is not present on the target");
                continue;
            }
            if (ProvisioningRequest.ATTR_GROUPS.equals(r.attribute())) {
                if (r.operation() == Operation.ADD) {
                    planGroupAdd(ctx, r.account(), r.value());
                } else {
                    planGroupRemove(ctx, r.account(), r.value());
                }
            } else if (r.operation() == Operation.ADD) {
                planDirectAdd(ctx, r.account(), r.directPath(), r.directPermissions());
            } else {
                planDirectRemove(ctx, r.account(), r.directPath());
            }
        }
        resolveConflicts(ctx);
        addMasks(ctx);
        List<ChangeStep> ordered = new ArrayList<>(ctx.steps);
        ordered.sort(ORDER);
        return new ChangePlan(ordered, ctx.warnings, ctx.satisfied);
    }

    /**
     * Drops an ADD when the same request list also removes the same access,
     * before any state is consulted. Checking at step level alone misses the
     * case where the removal is already satisfied and produces no step, which
     * would let the grant through.
     */
    private static List<ProvisioningRequest> revokeWins(Context ctx, List<ProvisioningRequest> requests) {
        Set<String> removals = new TreeSet<>();
        for (ProvisioningRequest r : requests) {
            if (r.operation() == Operation.REMOVE) {
                removals.add(conflictKey(r));
            }
        }
        List<ProvisioningRequest> kept = new ArrayList<>();
        for (ProvisioningRequest r : requests) {
            if (r.operation() == Operation.ADD && removals.contains(conflictKey(r))) {
                ctx.warn(PlanWarning.Code.CONFLICTING_REQUESTS, r.account(),
                        "add and remove of " + r.attribute() + " " + r.value() + " in one plan; the removal is kept");
            } else {
                kept.add(r);
            }
        }
        return kept;
    }

    private static String conflictKey(ProvisioningRequest r) {
        String target = ProvisioningRequest.ATTR_GROUPS.equals(r.attribute()) ? r.value() : r.directPath();
        return r.account() + "\u0000" + r.attribute() + "\u0000" + target;
    }

    private void planGroupAdd(Context ctx, String account, String groupName) {
        Optional<ShareEntitlement> ent = catalog.forGroup(groupName);
        Optional<Group> existing = ctx.snapshot.group(groupName);
        if (existing.isEmpty() && !ctx.createdGroups.contains(groupName)) {
            if (ent.isEmpty()) {
                ctx.warn(PlanWarning.Code.UNKNOWN_ENTITLEMENT, account,
                        groupName + " is neither on the target nor in the entitlement catalog");
                return;
            }
            Optional<Group> clash = ctx.snapshot.groupByGid(ent.get().gid());
            if (clash.isPresent()) {
                ctx.warn(PlanWarning.Code.GID_CONFLICT, account,
                        "gid " + ent.get().gid() + " for " + groupName + " is already used by " + clash.get().name());
                return;
            }
            ctx.steps.add(new ChangeStep.CreateGroup(groupName, ent.get().gid()));
            ctx.createdGroups.add(groupName);
        }
        if (ent.isPresent() && !bindGroup(ctx, account, ent.get())) {
            return;
        }
        if (existing.isPresent() && existing.get().members().contains(account)) {
            ctx.satisfied.add(account + " is already a member of " + groupName);
        } else {
            ctx.steps.add(new ChangeStep.AddMembership(account, groupName));
        }
    }

    private boolean bindGroup(Context ctx, String account, ShareEntitlement ent) {
        Optional<PathEntry> path = ctx.snapshot.path(ent.path());
        if (path.isEmpty()) {
            ctx.warn(PlanWarning.Code.PATH_NOT_FOUND, account, ent.path() + " for " + ent.group() + " is not on the target");
            return false;
        }
        if (!path.get().aclEnabled()) {
            ctx.warn(PlanWarning.Code.ACL_NOT_SUPPORTED, account,
                    ent.path() + " is on a " + path.get().filesystem() + " mount without ACL support");
            return false;
        }
        ensureEntry(ctx, ent.path(), AclEntry.access(AclTag.GROUP, ent.group(), ent.permissions()));
        if (ent.inherit() && path.get().directory()) {
            ensureEntry(ctx, ent.path(), AclEntry.defaults(AclTag.GROUP, ent.group(), ent.permissions()));
        }
        return true;
    }

    private void planGroupRemove(Context ctx, String account, String groupName) {
        Optional<Group> group = ctx.snapshot.group(groupName);
        if (group.isEmpty() || !group.get().members().contains(account)) {
            ctx.satisfied.add(account + " is not a direct member of " + groupName);
        } else {
            ctx.steps.add(new ChangeStep.RemoveMembership(account, groupName));
        }
        Set<String> via = new GroupResolver(ctx.snapshot).alternatePathsTo(account, groupName, groupName);
        if (!via.isEmpty()) {
            ctx.warn(PlanWarning.Code.RESIDUAL_ACCESS, account,
                    account + " still reaches " + groupName + " through nested group(s) " + via);
        }
    }

    private void planDirectAdd(Context ctx, String account, String pathName, PermissionSet perms) {
        Optional<PathEntry> path = ctx.snapshot.path(pathName);
        if (path.isEmpty()) {
            ctx.warn(PlanWarning.Code.PATH_NOT_FOUND, account, pathName + " is not on the target");
            return;
        }
        if (!path.get().aclEnabled()) {
            ctx.warn(PlanWarning.Code.ACL_NOT_SUPPORTED, account, pathName + " does not support ACLs");
            return;
        }
        ensureEntry(ctx, pathName, AclEntry.access(AclTag.USER, account, perms));
        if (path.get().directory()) {
            ensureEntry(ctx, pathName, AclEntry.defaults(AclTag.USER, account, perms));
        }
    }

    private void planDirectRemove(Context ctx, String account, String pathName) {
        Optional<PathEntry> path = ctx.snapshot.path(pathName);
        if (path.isEmpty()) {
            ctx.satisfied.add(pathName + " is not on the target");
            return;
        }
        boolean any = false;
        for (boolean scope : new boolean[] {true, false}) {
            if (path.get().acl().find(AclTag.USER, account, scope).isPresent()) {
                ctx.steps.add(new ChangeStep.RemoveAclEntry(pathName, AclTag.USER, account, scope));
                any = true;
            }
        }
        if (!any) {
            ctx.satisfied.add(account + " holds no direct entry on " + pathName);
        }
    }

    private void ensureEntry(Context ctx, String path, AclEntry entry) {
        Acl current = ctx.snapshot.path(path).orElseThrow().acl();
        Optional<AclEntry> found = current.find(entry.tag(), entry.qualifier(), entry.defaultScope());
        if (found.isPresent() && found.get().permissions().equals(entry.permissions())) {
            ctx.satisfied.add(entry.toText() + " already present on " + path);
            return;
        }
        ctx.steps.add(new ChangeStep.SetAclEntry(path, entry));
    }

    private void resolveConflicts(Context ctx) {
        Set<ChangeStep> drop = new LinkedHashSet<>();
        for (ChangeStep s : ctx.steps) {
            if (s instanceof ChangeStep.AddMembership add
                    && ctx.steps.contains(new ChangeStep.RemoveMembership(add.account(), add.group()))) {
                drop.add(s);
                ctx.warn(PlanWarning.Code.CONFLICTING_REQUESTS, add.account(),
                        "add and remove of " + add.group() + " in one plan; the removal is kept");
            }
            if (s instanceof ChangeStep.SetAclEntry set) {
                AclEntry e = set.entry();
                if (ctx.steps.contains(new ChangeStep.RemoveAclEntry(set.path(), e.tag(), e.qualifier(), e.defaultScope()))) {
                    drop.add(s);
                    ctx.warn(PlanWarning.Code.CONFLICTING_REQUESTS, e.qualifier(),
                            "set and remove of " + e.toText() + " on " + set.path() + "; the removal is kept");
                }
            }
        }
        ctx.steps.removeAll(drop);
    }

    private void addMasks(Context ctx) {
        Map<String, Acl> predicted = new TreeMap<>();
        for (ChangeStep s : ctx.steps) {
            String path = AclOps.pathOf(s);
            if (path != null) {
                Acl acl = predicted.computeIfAbsent(path, p -> ctx.snapshot.path(p).orElseThrow().acl());
                predicted.put(path, AclOps.apply(acl, s));
            }
        }
        for (Map.Entry<String, Acl> e : predicted.entrySet()) {
            Acl acl = e.getValue();
            for (boolean scope : new boolean[] {false, true}) {
                Optional<AclEntry> mask = acl.find(AclTag.MASK, null, scope);
                if (!acl.hasNamedEntries(scope) && mask.isEmpty()) {
                    continue;
                }
                PermissionSet computed = acl.computedMask(scope);
                if (mask.isEmpty() || !mask.get().permissions().equals(computed)) {
                    ctx.steps.add(new ChangeStep.SetMask(e.getKey(), scope, computed));
                }
            }
        }
    }

    private static final class Context {
        final FilesystemSnapshot snapshot;
        final Set<ChangeStep> steps = new LinkedHashSet<>();
        final List<PlanWarning> warnings = new ArrayList<>();
        final List<String> satisfied = new ArrayList<>();
        final Set<String> createdGroups = new TreeSet<>();

        Context(FilesystemSnapshot snapshot) {
            this.snapshot = snapshot;
        }

        void warn(PlanWarning.Code code, String account, String detail) {
            warnings.add(new PlanWarning(code, account, detail));
        }
    }
}
