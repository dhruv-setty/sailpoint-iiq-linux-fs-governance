package io.github.whatheheckisthis.fsgov.evidence;

import io.github.whatheheckisthis.fsgov.model.AclEntry;
import io.github.whatheheckisthis.fsgov.model.AclTag;
import io.github.whatheheckisthis.fsgov.model.EntitlementCatalog;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.GroupResolver;
import io.github.whatheheckisthis.fsgov.model.NfsClientRule;
import io.github.whatheheckisthis.fsgov.model.NfsExport;
import io.github.whatheheckisthis.fsgov.model.PathEntry;
import io.github.whatheheckisthis.fsgov.model.ShareEntitlement;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Detects orphaned, unowned and unsafe access on legacy shares. Legacy hosts
 * accumulate numeric owners left by deleted accounts, ACL entries naming
 * groups that no longer exist, and exports opened with no_root_squash for a
 * long forgotten backup host. These findings feed the certification as
 * items with no natural reviewer, routed to the share's business owner.
 */
public final class OrphanDetector {

    private static final Comparator<Finding> ORDER = Comparator
            .comparing(Finding::type)
            .thenComparing(Finding::path)
            .thenComparing(Finding::subject);

    private final FilesystemSnapshot snapshot;
    private final EntitlementCatalog catalog;

    public OrphanDetector(FilesystemSnapshot snapshot, EntitlementCatalog catalog) {
        this.snapshot = snapshot;
        this.catalog = catalog;
    }

    public List<Finding> detect() {
        List<Finding> out = new ArrayList<>();
        for (PathEntry p : snapshot.paths().values()) {
            inspectPath(p, out);
        }
        GroupResolver resolver = new GroupResolver(snapshot);
        for (ShareEntitlement e : catalog.all()) {
            if (snapshot.group(e.group()).isPresent() && resolver.effectiveMembers(e.group()).isEmpty()) {
                out.add(new Finding(FindingType.EMPTY_GOVERNED_GROUP, e.path(), e.group(), "no effective members"));
            }
        }
        for (String g : resolver.cycles()) {
            out.add(new Finding(FindingType.NESTING_CYCLE, "", g, "group is part of a nesting cycle"));
        }
        for (NfsExport x : snapshot.exports()) {
            for (NfsClientRule r : x.clients()) {
                if (!r.rootSquash()) {
                    out.add(new Finding(FindingType.NO_ROOT_SQUASH, x.path(), r.client(),
                            "remote root acts as local root on this export"));
                }
            }
        }
        out.sort(ORDER);
        return out;
    }

    private void inspectPath(PathEntry p, List<Finding> out) {
        String uid = Integer.toString(p.uid());
        if (snapshot.accountByUid(p.uid()).isEmpty()) {
            out.add(new Finding(FindingType.UNOWNED_PATH, p.path(), uid, "owner uid has no account"));
        }
        if (snapshot.groupByGid(p.gid()).isEmpty()) {
            out.add(new Finding(FindingType.UNKNOWN_GROUP_OWNER, p.path(), Integer.toString(p.gid()),
                    "owning gid has no group"));
        }
        for (AclEntry e : p.acl().entries()) {
            if (e.tag() == AclTag.USER && !resolvesUser(e.qualifier())) {
                out.add(new Finding(FindingType.DANGLING_ACL_USER, p.path(), e.qualifier(), e.toText()));
            } else if (e.tag() == AclTag.GROUP && !resolvesGroup(e.qualifier())) {
                out.add(new Finding(FindingType.DANGLING_ACL_GROUP, p.path(), e.qualifier(), e.toText()));
            }
        }
        boolean governed = catalog.governs(p.path());
        if (!governed) {
            out.add(new Finding(FindingType.UNGOVERNED_PATH, p.path(), "", "no governed share covers this path"));
        }
        boolean otherWrite = p.mode().other().write();
        if (otherWrite && (!p.directory() || !p.mode().sticky())) {
            out.add(new Finding(FindingType.WORLD_WRITABLE, p.path(), "", "mode " + p.mode()));
        }
        if (governed && !p.aclEnabled()) {
            out.add(new Finding(FindingType.ACL_DISABLED, p.path(), p.filesystem().name(),
                    "governed path on a mount without ACL support"));
        }
    }

    private boolean resolvesUser(String q) {
        if (snapshot.account(q).isPresent()) {
            return true;
        }
        return q.matches("\\d+") && snapshot.accountByUid(Integer.parseInt(q)).isPresent();
    }

    private boolean resolvesGroup(String q) {
        if (snapshot.group(q).isPresent()) {
            return true;
        }
        return q.matches("\\d+") && snapshot.groupByGid(Integer.parseInt(q)).isPresent();
    }
}
