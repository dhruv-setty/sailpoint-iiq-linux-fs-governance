package io.github.whatheheckisthis.fsgov;

import io.github.whatheheckisthis.fsgov.model.Account;
import io.github.whatheheckisthis.fsgov.model.Acl;
import io.github.whatheheckisthis.fsgov.model.AclEntry;
import io.github.whatheheckisthis.fsgov.model.EntitlementCatalog;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.FilesystemType;
import io.github.whatheheckisthis.fsgov.model.Group;
import io.github.whatheheckisthis.fsgov.model.NfsClientRule;
import io.github.whatheheckisthis.fsgov.model.NfsExport;
import io.github.whatheheckisthis.fsgov.model.PathEntry;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;
import io.github.whatheheckisthis.fsgov.model.PosixMode;
import io.github.whatheheckisthis.fsgov.model.ShareEntitlement;

import java.util.List;
import java.util.Set;

/** A small legacy estate used across tests: finance and audit shares on ext4 and XFS. */
public final class Fixtures {

    public static final String FINANCE = "/srv/finance";
    public static final String AUDIT = "/srv/audit";
    public static final String SCRATCH = "/srv/scratch";

    private Fixtures() {
    }

    public static Acl baseAcl(String mode) {
        return Acl.fromMode(PosixMode.parse(mode));
    }

    public static FilesystemSnapshot estate() {
        Acl financeAcl = Acl.of(List.of(
                AclEntry.parse("user::rwx"),
                AclEntry.parse("group::r-x"),
                AclEntry.parse("group:fs_fin_ro:r-x"),
                AclEntry.parse("mask::r-x"),
                AclEntry.parse("other::---"),
                AclEntry.parse("default:user::rwx"),
                AclEntry.parse("default:group::r-x"),
                AclEntry.parse("default:group:fs_fin_ro:r-x"),
                AclEntry.parse("default:mask::r-x"),
                AclEntry.parse("default:other::---")));
        return FilesystemSnapshot.builder()
                .account(new Account("root", 0, 0))
                .account(new Account("alice", 1001, 1001))
                .account(new Account("bob", 1002, 1002))
                .account(new Account("carol", 1003, 1003))
                .account(new Account("finsvc", 990, 990))
                .group(Group.of("root", 0))
                .group(Group.of("alice", 1001))
                .group(Group.of("bob", 1002))
                .group(Group.of("carol", 1003))
                .group(Group.of("finsvc", 990))
                .group(Group.of("fs_fin_ro", 4100, "bob"))
                .group(Group.of("fs_audit_ro", 4200))
                .path(PathEntry.directory(FINANCE, 990, 990, PosixMode.parse("2750"), financeAcl, FilesystemType.EXT4))
                .path(PathEntry.directory(AUDIT, 0, 0, PosixMode.parse("0750"), baseAcl("0750"), FilesystemType.XFS))
                .path(new PathEntry(SCRATCH, 0, 0, PosixMode.parse("1777"), null, FilesystemType.EXT3, true, false))
                .export(new NfsExport(FINANCE, List.of(
                        new NfsClientRule("10.20.0.0/16", List.of("rw", "sync", "root_squash")),
                        new NfsClientRule("backup01", List.of("ro", "no_root_squash")))))
                .build();
    }

    public static EntitlementCatalog catalog() {
        return EntitlementCatalog.of(
                new ShareEntitlement("fs_fin_ro", 4100, FINANCE, PermissionSet.READ_EXECUTE, true, "finance.owner"),
                new ShareEntitlement("fs_fin_rw", 4101, FINANCE, PermissionSet.ALL, true, "finance.owner"),
                new ShareEntitlement("fs_audit_ro", 4200, AUDIT, PermissionSet.READ_EXECUTE, true, "audit.owner"),
                new ShareEntitlement("fs_audit_rw", 4201, AUDIT, PermissionSet.ALL, true, "audit.owner"),
                new ShareEntitlement("fs_scratch_rw", 4300, SCRATCH, PermissionSet.ALL, false, "it.owner"));
    }

    public static Set<String> accounts() {
        return Set.of("alice", "bob", "carol");
    }
}
