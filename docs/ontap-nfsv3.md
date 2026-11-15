# ONTAP NFSv3 Module (C#)

`src/OntapNfs` is a .NET 8 solution for the storage side of the estate this
project governs: NetApp ONTAP volumes published over NFSv3 to Linux and
Windows application hosts, and the Java application servers that read their
WAR files from those shares. It is operations tooling that runs beside
IdentityIQ. It is not loaded into IdentityIQ and shares no code with the Java
modules; the two meet in the state they both read and write (UNIX users and
groups, export rules, file ownership on the share).

## Components

| Project | Namespace | Role |
|---|---|---|
| `OntapNfs.Core` | `OntapNfs.Core.FileAccess` | `NfsShare`: System.IO access to a mounted share with explicit `FileShare` modes, retry with backoff on transient `IOException`, atomic write through a temporary file and rename. `NfsPathGuard`: rejects traversal, rooted input, backslashes, NUL and symbolic links that leave the root. `IoErrorClassifier`, `RetryPolicy`, `MountTable` (parses `/proc/self/mounts`). |
| `OntapNfs.Core` | `OntapNfs.Core.Posix` | UNIX identity and export policy model: `UnixUser`, `UnixGroup`, `ExportRule`, `ExportPolicy`, `ClientMatcher`, `ExportAccessEvaluator`, `PosixPermissions`, `LinuxFileOwnershipReader` (statx), `ServiceAccountValidator`. |
| `OntapNfs.Ontap` | `OntapNfs.Ontap` | `OntapClient` for the ONTAP REST API with Basic authentication and job polling, `ExportRuleMapper`, and `OntapNfsReconciler` with idempotent ensure operations. |
| `OntapNfs.Deploy` | `OntapNfs.Deploy` | `WarDeployer`: atomic WAR placement for Tomcat, WildFly (marker files) and Jetty. |
| `OntapNfs.Tests` | | xUnit. The ONTAP client runs against a fake `HttpMessageHandler`; file tests run in temporary directories. |

REST endpoints used:

| Endpoint | Operations |
|---|---|
| `/api/storage/volumes` | list, get by SVM and name, PATCH `nas.export_policy` (asynchronous, job polled) |
| `/api/protocols/nfs/export-policies` | list, get, create |
| `/api/protocols/nfs/export-policies/{id}/rules` | list, create, PATCH by index |
| `/api/name-services/unix-users` | list (by name or UID), create, PATCH `/{svm.uuid}/{name}` |
| `/api/name-services/unix-groups` | list (by name or GID, with members), create, PATCH, add and remove members |
| `/api/protocols/nfs/services` | read `enabled`, `state`, `protocol.v3_enabled` |
| `/api/cluster/jobs/{uuid}` | poll until `success` or `failure` |

## Two ways to put an NFSv3 share in front of an application

```text
 (a) ONTAP native NFSv3                       (b) SAN LUN re-exported by Linux

  app host (Linux / Windows NFS client)        app host (Linux / Windows NFS client)
        |  NFSv3, NLM, NSM, MOUNT                    |  NFSv3, NLM, NSM, MOUNT
        v                                            v
  ONTAP SVM data LIF                           Linux NFS server (kernel nfsd)
   export policy + rules                        /etc/exports
   unix-user / unix-group or LDAP               /etc/passwd, /etc/group or SSSD
        |                                            |  ext3 / ext4 / XFS
  FlexVol volume on WAFL                       dm-multipath device
                                                     |  iSCSI or FC
                                               ONTAP SVM SAN LIF, igroup, LUN
                                                     |
                                               FlexVol volume on WAFL
```

### (a) ONTAP native NFSv3 export

The volume is a FlexVol (or FlexGroup) on WAFL. There is no ext3, ext4 or XFS
decision to make: ONTAP owns the on disk format, journaling, snapshots and
space efficiency. What the administrator chooses is the volume's security
style (`unix` for this use), its junction path, the root directory owner,
group and mode (`nas.uid`, `nas.gid`, `nas.unix_permissions`), and the export
policy assigned to the volume and, where needed, to qtrees.

Access is decided by the export policy on the SVM. Rules are evaluated in
index order and the first rule whose `clientmatch` fits the client wins; no
match means no access. Each rule carries:

| Field | Meaning for an NFSv3 AUTH_SYS client |
|---|---|
| `clientmatch` | IP, CIDR, host name, `.domain` suffix, `@netgroup`, or `0.0.0.0/0`. |
| `rorule` | `sys` or `any` grants read as the asserted UID; `none` grants read as anonymous; `never` or a list without `sys` denies. |
| `rwrule` | Same values for write. Write without read is no access. |
| `superuser` | `sys` or `any` keeps UID 0; anything else squashes root to the anonymous user (root squash). |
| `anon` | The anonymous UID. 65534 by default; 65535 denies every request that maps to anonymous; 0 gives anonymous requests root. |
| `protocol` | `nfs3`, `nfs`, `any`, or protocols that do not include NFSv3, in which case the rule is skipped. |

`ExportAccessEvaluator` implements exactly this table, and
`OntapNfsReconciler.EnsureExportRuleAsync` keeps a rule in that shape. A rule
is identified by its client match set rather than its index, because indexes
shift when rules are inserted. A typical rule for application hosts in ONTAP
CLI form, with the equivalent C# call:

```text
vserver export-policy create -vserver svm1 -policyname app_nfs
vserver export-policy rule create -vserver svm1 -policyname app_nfs -ruleindex 1 -clientmatch 10.20.0.0/16 -protocol nfs3 -rorule sys -rwrule sys -superuser none -anon 65534
volume modify -vserver svm1 -volume vol1 -policy app_nfs
```

```csharp
var reconciler = new OntapNfsReconciler(new OntapClient(http, OntapClientOptions.FromEnvironment()));
await reconciler.EnsureExportRuleAsync("svm1", "app_nfs",
    ExportRule.ForSys(1, "10.20.0.0/16", readWrite: true, rootSquash: true));
await reconciler.EnsureVolumeExportPolicyAsync("svm1", "vol1", "app_nfs");
```

A Linux client mount for this path:

```text
svm1-data:/vol1  /mnt/ontap/vol1  nfs  vers=3,proto=tcp,hard,rsize=65536,wsize=65536,timeo=600,retrans=2,sec=sys,_netdev  0 0
```

Use `hard` mounts for anything an application writes. A `soft` mount turns a
slow server into `EIO` in the middle of a write; `MountEntry.IsSoft` lets a
deployment check refuse one.

### (b) SAN LUN, Linux file system, kernel NFS server

ONTAP presents a LUN over iSCSI or FC to an igroup containing one Linux
server. That server discovers it through dm-multipath, creates a file system
on it, mounts it and re-exports it with the kernel NFS server. ONTAP sees
only blocks: it snapshots and replicates the LUN, but the file system, its
ownership and its ACLs are the Linux server's. This is the "legacy Linux file
server" shape the rest of this repository governs, now with ONTAP underneath.

```text
/etc/fstab
/dev/mapper/app_lun0  /srv/export/apps  xfs  defaults,_netdev,inode64  0 0

/etc/exports
/srv/export/apps  10.20.0.0/16(rw,sync,root_squash,anonuid=65534,anongid=65534,sec=sys,no_subtree_check,fsid=101)
```

Notes that differ from path (a):

* The LUN must be attached to exactly one host at a time. ext3, ext4 and XFS
  are not cluster file systems; two hosts mounting the same LUN read write
  will corrupt it. High availability means a Pacemaker style failover of the
  LUN, the mount, a floating IP and nfsd together, with `/var/lib/nfs` on the
  shared storage so NSM state survives the move.
* Give each export a stable `fsid=` so file handles stay valid across a
  failover; otherwise clients see `ESTALE`.
* NFSv3 needs rpcbind, mountd, lockd (NLM) and statd (NSM). Pin their ports
  (`/etc/nfs.conf`) so a firewall can allow them.
* `sync` is the safe default; `async` acknowledges writes before they reach
  the LUN and loses them if the server crashes.
* ACLs are POSIX.1e on the Linux file system and reach NFSv3 clients only
  through the NFSACL side band protocol. The existing `fsgov-core` planner
  and the host executor provision them on this server exactly as on any other
  legacy host.

### Choosing the file system for path (b)

| | ext3 | ext4 | XFS |
|---|---|---|---|
| Status | Legacy; kept for existing volumes, mounted by the ext4 driver on current kernels | General purpose default on many distributions | Default on RHEL 7 and later |
| Allocation | Block mapped, indirect blocks | Extents, delayed allocation | Extents, delayed allocation, allocation groups |
| Large files | 2 TiB file limit at 4 KiB blocks; slow deletes of large files | 16 TiB file limit; good | 8 EiB; best for multi GiB WAR, log and archive files |
| Parallel I/O | Single journal, limited concurrency | Better, still one journal | Allocation groups let many writers allocate in parallel; scales with nfsd threads |
| Timestamps | 1 second resolution | Nanosecond (256 byte inodes) | Nanosecond |
| Shrink | Offline | Offline | Not supported, grow only |
| Repair | Long fsck on large volumes | Faster fsck (uninit_bg, flex_bg) | `xfs_repair`, no routine boot time check |
| ACLs | Needs the `acl` mount option on older distributions | Default on | Always on |

Recommendation: XFS for new LUNs that hold application artefacts, archives or
large sequential files; ext4 where the estate already standardises on it or
the volume may need to shrink; ext3 only to keep an existing volume running
until migration. One second timestamps on ext3 matter here: two updates in
the same second look identical to an NFS client's attribute cache and to any
change detection by modification time, including application server
deployment scanners.

### Comparing the paths

| Concern | (a) ONTAP native | (b) LUN re-exported by Linux |
|---|---|---|
| Who enforces permissions | ONTAP, from export rules and the volume's UNIX permissions | Linux nfsd, from `/etc/exports`, mode bits and POSIX ACLs |
| Identity source | ONTAP unix-user and unix-group, or LDAP or NIS on the SVM | `/etc/passwd`, `/etc/group`, or SSSD on the server |
| High availability | Built in: LIF failover, takeover and giveback, NLM state held by ONTAP | Build it yourself; single server otherwise |
| Snapshots seen by users | `.snapshot` directory, per volume | LUN snapshots only, not visible to NFS clients without a separate mount |
| File system choice | None (WAFL) | ext3, ext4 or XFS |
| Locking | ONTAP NLM service | Kernel lockd and statd on the server |
| Fit with this repository | Govern ONTAP unix-groups through the REST API (`OntapNfsReconciler`) | Govern the Linux server as a legacy host (`fsgov-core`, host executor) |

## UID and GID mapping requirements

NFSv3 with AUTH_SYS carries numbers, not names. The client asserts a UID, a
primary GID and up to 16 supplementary GIDs, and the server trusts them.
Everything below follows from that.

* Every client and the server must agree on the number for each name. On
  ONTAP the server side is the SVM's unix-user and unix-group tables or its
  LDAP or NIS configuration; on path (b) it is the Linux server's name
  service. A UID that means `svc_tomcat` on one host and someone else on
  another hands that person the service account's files.
* A UID or GID must belong to one name. `EnsureUnixUserAsync` and
  `EnsureUnixGroupAsync` refuse to assign a number already held by another
  name, the same rule the change planner applies (`GID_CONFLICT`).
* AUTH_SYS sends at most 16 supplementary groups. A seventeenth group is
  silently missing from the request. ONTAP can look groups up itself
  (`-auth-sys-extended-groups enabled`); otherwise keep service accounts in
  few groups. The validator reports `AUTH_SYS_GROUP_LIMIT` and evaluates the
  truncated list.
* Root squash maps UID 0 to the anonymous user unless the rule's superuser
  allows the flavour. Run application servers as a dedicated unprivileged
  account, never root.
* Files created by a squashed or anonymous request are owned by the anonymous
  UID (65534, `nobody`), not by the service account. The validator treats
  this as an error when the account needs write.

`ServiceAccountValidator.Validate` (or
`OntapNfsReconciler.ValidateServiceAccountAsync` against a live SVM) checks a
service account end to end and returns stable codes:

| Code | Severity | Meaning |
|---|---|---|
| `USER_NOT_FOUND` | Error | The name is not a UNIX user on the SVM. |
| `RESERVED_UID` | Error | UID 65534, 65535 or out of range. |
| `DUPLICATE_UID` | Error | Another user has the same UID. |
| `PRIMARY_GROUP_MISSING` | Error | The primary GID is not a group. |
| `DUPLICATE_GID` | Warning | The primary GID has more than one name. |
| `AUTH_SYS_GROUP_LIMIT` | Warning | More than 16 supplementary groups. |
| `RUNS_AS_ROOT` | Warning | The account is UID 0. |
| `EXPORT_DENIED` | Error | No rule grants this client access. |
| `WRITE_NOT_ALLOWED` | Error | Write is needed and the rule is read only. |
| `ROOT_SQUASHED` | Warning | UID 0 is squashed. |
| `MAPPED_TO_ANONYMOUS` | Error when writing, otherwise Warning | Requests run as the anonymous UID. |
| `ANON_IS_ROOT` | Error | `anon=0`. |
| `DIRECTORY_NOT_READABLE`, `DIRECTORY_NOT_WRITABLE` | Error | Mode bits on the target directory deny the effective identity. |
| `NFSV3_DISABLED`, `VOLUME_NOT_EXPORTED` | Error | From the live SVM check only. |

On Linux, `LinuxFileOwnershipReader` reads owner, group and mode of a path on
the mounted share with `statx(2)`, so a deployment can confirm what the
server actually recorded rather than what it expected.

## NFSv3 locking

NFSv3 itself is stateless and has no locks. Locking is a separate pair of
protocols: NLM (lockd) for the locks and NSM (statd) to tell peers about
reboots so locks can be reclaimed during the server's grace period.

* Locks are advisory. They exclude only writers that also lock.
* The Linux client implements `flock()` on NFS as a whole file NLM byte range
  lock (since kernel 2.6.12). .NET on Linux takes `flock(LOCK_EX)` for
  `FileShare.None` and `flock(LOCK_SH)` for any other share mode, so
  `NfsShare.OpenExclusive` is a cross client mutex between cooperating
  processes.
* Mounting with `nolock` or `local_lock=all` keeps locks on the client and
  removes that protection silently. `MountEntry.HasNoLock` exposes it.
* A lock conflict surfaces as `EAGAIN` (or a Windows sharing violation) and
  an unavailable lock manager as `ENOLCK`. `IoErrorClassifier` treats both as
  lock contention and `RetryPolicy` backs off and retries; `ESTALE`, `EIO`
  on soft mounts and `ETIMEDOUT` are retried too, each attempt reopening by
  path. Missing files, permission errors and traversal are never retried.
* On ONTAP, NLM state lives on the SVM and survives LIF migration; on path
  (b) it lives in `/var/lib/nfs` on the server.

Atomic replacement does not need a lock. `NfsShare.WriteAtomicAsync` writes a
hidden `.name.<random>.tmp` in the destination directory, flushes it to the
server (NFS COMMIT), and renames it over the target. NFSv3 RENAME is atomic
on the server, so another client sees the old file or the new one, never a
partial one, once its attribute cache revalidates (close to open consistency:
the next open of the file checks with the server).

## Windows NFS client

Windows Server and Windows Enterprise include "Client for NFS", which speaks
NFSv2 and NFSv3 only. A share is mounted to a drive letter or used by UNC
path:

```text
mount -o mtype=hard,rsize=32,wsize=32,timeout=60,sec=sys \\svm1-data\vol1 N:
dir \\svm1-data\vol1
```

Windows accounts have no UID. Without identity mapping (Active Directory
`uidNumber` and `gidNumber`, or AD LDS) the client sends the anonymous
identity from the registry, which defaults to -2:

```text
HKLM\SOFTWARE\Microsoft\ClientForNFS\CurrentVersion\Default
  AnonymousUid  REG_DWORD  1201
  AnonymousGid  REG_DWORD  1201
```

Set these to the service account's UID and GID and restart the client
(`nfsadmin client stop`, `nfsadmin client start`). Every process on that
host then writes as that UID, so use this only on a host dedicated to the
application. The export must allow the host's IP, and the validator check is
the same as for a Linux client with that UID.

`NfsShare` and `NfsPathGuard` accept `N:\` or `\\svm1-data\vol1` as the root;
relative paths are always written with forward slashes. Share modes on
Windows are enforced by the local redirector and byte range locks are sent as
NLM locks. `LinuxFileOwnershipReader` is Linux only; on Windows, ownership is
read from ONTAP (`nas.uid`, `nas.gid`, `nas.unix_permissions`) instead.

## Java application servers reading a WAR over NFS

The application server mounts the share and points its deployment directory
at it. What goes wrong is almost always a scanner seeing a file before it is
complete, or a file being changed under a running class loader.

* **Never copy in place.** A JVM reads a WAR's central directory once and
  keeps the file open. Overwriting it in place corrupts the running
  application. Renaming a new file over it is safe: the old file stays alive
  for its open handles (on NFS the client keeps it as a hidden `.nfsXXXX`
  "silly rename" until it is closed), and the next open gets the new file.
  `WarDeployer` always copies to a hidden `.tmp` and renames.
* **Tomcat** (`$CATALINA_BASE/webapps`, `autoDeploy="true"`) redeploys when
  `name.war` changes. Keep `work/` and, if `unpackWARs="true"`, consider a
  local `appBase` copy, because expansion writes thousands of small files to
  the share. The deployment name becomes the context path; `#` nests it
  (`api#v2.war` serves `/api/v2`).
* **WildFly and JBoss EAP** (`standalone/deployments`) use the deployment
  scanner. `WarDeployer` in WildFly mode clears stale `.failed`,
  `.undeployed` and `.pending` markers, places the WAR, writes
  `name.war.dodeploy`, and polls until the scanner removes it and writes
  `name.war.deployed`, or writes `name.war.failed` (whose content is returned
  as the failure). It never deletes `.deployed`, because that undeploys the
  running application. Set the scanner's `scan-interval` and the poll
  interval above the client's attribute cache time (`actimeo`) so a marker is
  not missed or seen late.
* **Jetty** (`$JETTY_BASE/webapps`) deploys `name.war` through the
  deployment manager's scanner and ignores hidden files, so the `.tmp` is
  invisible until it is renamed.
* The deployment directory must be writable by the deployer's effective UID
  and readable by the server's. Run `ServiceAccountValidator` for both
  accounts with the directory's ownership before the first deployment.

```csharp
var share = new NfsShare("/mnt/ontap/vol1");
var deployer = new WarDeployer(share, new WarDeploymentOptions
{
    Kind = AppServerKind.WildFly,
    DeploymentDirectory = "opt/wildfly/standalone/deployments",
    PollInterval = TimeSpan.FromSeconds(5),
    MarkerTimeout = TimeSpan.FromMinutes(5),
});
var result = await deployer.DeployAsync("/build/identityiq.war", "identityiq");
// result.Status: Deployed, Failed (result.Message holds the .failed text) or TimedOut
```

## How this ties into the IdentityIQ provisioning model

The Java side of this repository governs access as POSIX groups named
`fs_<share>_<ro|rw>`, with the GID allocated from a reserved range and held
on the IdentityIQ ManagedAttribute (`fsgovGid`). Provisioning computes an
ordered change plan, revocation before grant, and a host executor applies it.

* **Path (b) changes nothing.** The Linux server that re-exports the LUN is a
  legacy file server like any other: the host collector reads `/etc/exports`,
  `getfacl` and the group database, `ExportsParser` and `AccessEvaluator`
  evaluate squash and read only options, and the executor applies
  `groupadd`, membership and `setfacl` steps.
* **Path (a) has no host to run `groupadd` or `setfacl`.** The governed
  group lives in the SVM's unix-group table (or in LDAP, which ONTAP then
  reads). `OntapNfsReconciler.EnsureUnixGroupAsync` creates it with the
  ManagedAttribute's GID and refuses a GID already used by another group, and
  `EnsureUnixGroupMembersAsync` with `removeOthers: true` applies grants and
  revocations, removing before adding as the planner does. Group permissions
  on the volume root (`nas.gid`, `nas.unix_permissions`) take the place of a
  named group ACL entry.
* **Export rules map to the existing export model.** `root_squash` is
  `superuser none`; `no_root_squash` is `superuser sys` and stays a hygiene
  finding; `rw` is `rwrule sys`; `anonuid` is `anon`. Reading the policy with
  `ReadExportPolicyAsync` gives certification evidence the same facts that
  `ExportsParser` gives for a Linux host.
* **Service accounts are identities too.** The IdentityIQ service account,
  the application server account and the deployer account each need a valid
  UID and GID on the SVM and the right export access. The validator turns
  that into a check that can run before go live and on a schedule.
* **IdentityIQ itself is a WAR on JBoss EAP 7.4** (`deploy/jboss-eap7`).
  `WarDeployer` in WildFly mode is an alternative to the CLI deployment when
  `standalone/deployments` is on an NFS share.

## Configuration and secrets

`OntapClientOptions.FromEnvironment` reads `ONTAP_BASE_URL` (https only),
`ONTAP_USERNAME` and `ONTAP_PASSWORD`. Nothing in the repository holds a
cluster address or credential. Use an ONTAP role limited to the endpoints
above. TLS validation is the default `HttpClient` behaviour; trust the
cluster's certificate through the host's trust store rather than by
disabling validation.

## Build and test

```text
dotnet test src/OntapNfs/OntapNfs.sln -c Release
```

CI runs this in a separate `dotnet` job on ubuntu with the .NET 8 SDK, beside
the unchanged Maven job.

## Verification status

* Unit tests cover the evaluator, validator, path guard, retry, mount table
  parsing, atomic writes and lock behaviour on a local file system, the REST
  client against recorded style JSON responses, and the WildFly marker
  protocol with a simulated scanner.
* Nothing here has run against a real ONTAP cluster. Request and response
  shapes follow the ONTAP 9 REST API reference and should be confirmed
  against the target ONTAP version, in particular the unix group member
  endpoints and the `anonymous_user` field.
* Nothing has run against a real NFSv3 mount, a Windows NFS client, or a
  running Tomcat, WildFly or Jetty. Locking, `ESTALE` and attribute cache
  behaviour on a real mount are described from protocol behaviour, not
  measured.
