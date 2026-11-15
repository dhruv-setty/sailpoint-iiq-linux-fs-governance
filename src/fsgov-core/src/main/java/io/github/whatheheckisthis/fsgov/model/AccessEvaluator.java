package io.github.whatheheckisthis.fsgov.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Evaluates effective rights with the POSIX.1e access check algorithm, with
 * NFSv3 export semantics (root_squash, all_squash, ro) layered on top.
 *
 * <p>For the group class the result is the union of every matching group
 * entry after masking. POSIX grants a request only when a single matching
 * entry holds all requested bits, so the union is the set of bits that can
 * each be obtained, which is the right measure for access review.</p>
 */
public final class AccessEvaluator {

    private final FilesystemSnapshot snapshot;
    private final GroupResolver resolver;

    public AccessEvaluator(FilesystemSnapshot snapshot) {
        this.snapshot = snapshot;
        this.resolver = new GroupResolver(snapshot);
    }

    public AccessDecision evaluate(String accountName, String path, AccessContext context) {
        Optional<PathEntry> entry = snapshot.path(path);
        if (entry.isEmpty()) {
            return AccessDecision.none("path not in snapshot");
        }
        Optional<Account> account = snapshot.account(accountName);
        if (account.isEmpty()) {
            return AccessDecision.none("account not in snapshot");
        }
        int uid = account.get().uid();
        Set<Integer> gids = resolver.effectiveGids(accountName);
        boolean readOnlyExport = false;
        String squashNote = "";

        if (context.isNfs()) {
            Optional<NfsClientRule> rule = snapshot.exportFor(path).flatMap(e -> e.ruleFor(context.nfsClient()));
            if (rule.isEmpty()) {
                return AccessDecision.none("not exported to " + context.nfsClient());
            }
            NfsClientRule r = rule.get();
            readOnlyExport = !r.readWrite();
            if (r.allSquash() || (uid == Account.ROOT_UID && r.rootSquash())) {
                uid = r.anonUid();
                gids = Set.of(r.anonGid());
                squashNote = r.allSquash() ? " after all_squash" : " after root_squash";
            }
        }

        AccessDecision decision = check(entry.get(), uid, gids);
        PermissionSet perms = decision.permissions();
        String source = decision.source() + squashNote;
        if (readOnlyExport && perms.write()) {
            perms = perms.minus(new PermissionSet(false, true, false));
            source = source + ", write removed by ro export";
        }
        return new AccessDecision(perms, source);
    }

    private AccessDecision check(PathEntry entry, int uid, Set<Integer> gids) {
        Acl acl = entry.acl();
        if (uid == Account.ROOT_UID) {
            boolean anyExec = entry.directory() || entry.mode().owner().execute()
                    || entry.mode().group().execute() || entry.mode().other().execute();
            return new AccessDecision(new PermissionSet(true, true, anyExec), "superuser");
        }
        if (entry.uid() == uid) {
            return new AccessDecision(acl.find(AclTag.USER_OBJ, null, false)
                    .map(AclEntry::permissions).orElse(entry.mode().owner()), "user::");
        }
        PermissionSet mask = acl.effectiveMask();
        boolean hasMask = acl.find(AclTag.MASK, null, false).isPresent();
        String accountName = snapshot.accountByUid(uid).map(Account::name).orElse(Integer.toString(uid));
        for (AclEntry e : acl.accessEntries()) {
            if (e.tag() == AclTag.USER && (e.qualifier().equals(accountName) || e.qualifier().equals(Integer.toString(uid)))) {
                return new AccessDecision(e.permissions().intersect(mask), e.toText() + " masked by " + mask);
            }
        }
        PermissionSet groupUnion = PermissionSet.NONE;
        List<String> matched = new ArrayList<>();
        for (AclEntry e : acl.accessEntries()) {
            boolean match = false;
            if (e.tag() == AclTag.GROUP_OBJ) {
                match = gids.contains(entry.gid());
            } else if (e.tag() == AclTag.GROUP) {
                match = gidOf(e.qualifier()).map(gids::contains).orElse(false);
            }
            if (match) {
                PermissionSet p = (e.tag() == AclTag.GROUP_OBJ && !hasMask) ? e.permissions() : e.permissions().intersect(mask);
                groupUnion = groupUnion.union(p);
                matched.add(e.toText());
            }
        }
        if (!matched.isEmpty()) {
            return new AccessDecision(groupUnion, String.join(" + ", matched) + (hasMask ? " masked by " + mask : ""));
        }
        return new AccessDecision(acl.find(AclTag.OTHER, null, false)
                .map(AclEntry::permissions).orElse(entry.mode().other()), "other::");
    }

    private Optional<Integer> gidOf(String qualifier) {
        Optional<Group> named = snapshot.group(qualifier);
        if (named.isPresent()) {
            return Optional.of(named.get().gid());
        }
        if (qualifier.matches("\\d+")) {
            return Optional.of(Integer.parseInt(qualifier));
        }
        return Optional.empty();
    }
}
