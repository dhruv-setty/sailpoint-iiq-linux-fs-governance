package io.github.whatheheckisthis.fsgov.plan;

import io.github.whatheheckisthis.fsgov.model.AclEntry;
import io.github.whatheheckisthis.fsgov.model.AclTag;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;

/**
 * One declarative change on a target host. Every step states the end state
 * it produces, so executing it a second time changes nothing.
 *
 * <p>{@link #equivalentCommand()} renders the step in familiar
 * groupadd, gpasswd and setfacl notation for reviewers and audit evidence.
 * It is descriptive text only. Nothing in this project executes it; the
 * host-side executor consumes the structured step.</p>
 */
public sealed interface ChangeStep permits ChangeStep.CreateGroup, ChangeStep.AddMembership,
        ChangeStep.RemoveMembership, ChangeStep.SetAclEntry, ChangeStep.RemoveAclEntry, ChangeStep.SetMask {

    Phase phase();

    /** Stable key used for ordering and deduplication within a phase. */
    String sortKey();

    String equivalentCommand();

    record CreateGroup(String group, int gid) implements ChangeStep {
        public Phase phase() {
            return Phase.CREATE_GROUP;
        }

        public String sortKey() {
            return group;
        }

        public String equivalentCommand() {
            return "groupadd -g " + gid + " " + group;
        }
    }

    record AddMembership(String account, String group) implements ChangeStep {
        public Phase phase() {
            return Phase.GRANT_MEMBERSHIP;
        }

        public String sortKey() {
            return group + "/" + account;
        }

        public String equivalentCommand() {
            return "gpasswd -a " + account + " " + group;
        }
    }

    record RemoveMembership(String account, String group) implements ChangeStep {
        public Phase phase() {
            return Phase.REVOKE_MEMBERSHIP;
        }

        public String sortKey() {
            return group + "/" + account;
        }

        public String equivalentCommand() {
            return "gpasswd -d " + account + " " + group;
        }
    }

    record SetAclEntry(String path, AclEntry entry) implements ChangeStep {
        public Phase phase() {
            return Phase.GRANT_ACL;
        }

        public String sortKey() {
            return path + "|" + entry.toText();
        }

        public String equivalentCommand() {
            return "setfacl -n -m " + entry.toText() + " " + path;
        }
    }

    record RemoveAclEntry(String path, AclTag tag, String qualifier, boolean defaultScope) implements ChangeStep {
        public Phase phase() {
            return Phase.REVOKE_ACL;
        }

        /** Default entries sort first so inheritance stops before current access is removed. */
        public String sortKey() {
            return path + "|" + (defaultScope ? "0" : "1") + "|" + tag + ":" + qualifier;
        }

        public String equivalentCommand() {
            return "setfacl -n -x " + (defaultScope ? "default:" : "") + tag.keyword() + ":" + qualifier + " " + path;
        }
    }

    record SetMask(String path, boolean defaultScope, PermissionSet mask) implements ChangeStep {
        public Phase phase() {
            return Phase.SET_MASK;
        }

        public String sortKey() {
            return path + "|" + defaultScope;
        }

        public String equivalentCommand() {
            return "setfacl -n -m " + (defaultScope ? "default:" : "") + "mask::" + mask + " " + path;
        }
    }
}
