package io.github.whatheheckisthis.fsgov.plan;

import io.github.whatheheckisthis.fsgov.model.Acl;
import io.github.whatheheckisthis.fsgov.model.AclEntry;
import io.github.whatheheckisthis.fsgov.model.AclTag;

/**
 * ACL edits with the side effects setfacl applies, shared by the planner (to
 * predict state) and the applier (to simulate it) so the two never disagree.
 */
final class AclOps {

    private AclOps() {
    }

    /**
     * Sets an entry. When the first default entry is added to a directory,
     * setfacl copies the access USER_OBJ, GROUP_OBJ and OTHER entries into the
     * default scope; this does the same.
     */
    static Acl set(Acl acl, AclEntry entry) {
        Acl result = acl;
        if (entry.defaultScope() && acl.defaultEntries().isEmpty()) {
            for (AclTag base : new AclTag[] {AclTag.USER_OBJ, AclTag.GROUP_OBJ, AclTag.OTHER}) {
                if (base != entry.tag()) {
                    AclEntry access = acl.find(base, null, false).orElseThrow();
                    result = result.with(AclEntry.defaults(base, null, access.permissions()));
                }
            }
        }
        return result.with(entry);
    }

    static Acl remove(Acl acl, AclTag tag, String qualifier, boolean defaultScope) {
        return acl.without(tag, qualifier, defaultScope);
    }

    static Acl apply(Acl acl, ChangeStep step) {
        if (step instanceof ChangeStep.SetAclEntry s) {
            return set(acl, s.entry());
        }
        if (step instanceof ChangeStep.RemoveAclEntry r) {
            return remove(acl, r.tag(), r.qualifier(), r.defaultScope());
        }
        if (step instanceof ChangeStep.SetMask m) {
            return acl.with(new AclEntry(AclTag.MASK, null, m.mask(), m.defaultScope()));
        }
        return acl;
    }

    static String pathOf(ChangeStep step) {
        if (step instanceof ChangeStep.SetAclEntry s) {
            return s.path();
        }
        if (step instanceof ChangeStep.RemoveAclEntry r) {
            return r.path();
        }
        if (step instanceof ChangeStep.SetMask m) {
            return m.path();
        }
        return null;
    }
}
