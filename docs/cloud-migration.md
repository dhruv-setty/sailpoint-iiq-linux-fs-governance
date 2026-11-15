# Cloud Migration Notes: Provisioning Files to Azure

These notes cover moving governed legacy share content, and the access model
that protects it, to Azure Files (NFS) or Azure NetApp Files, while keeping
IdentityIQ as the system of record for who may access what.

## Choosing a target

| Concern | Azure Files NFS | Azure NetApp Files (NFSv3 or NFSv4.1) |
|---|---|---|
| Protocol | NFS 4.1 only, premium (SSD) file shares | NFSv3, NFSv4.1, or dual protocol with SMB |
| POSIX mode bits | Supported | Supported |
| POSIX.1e ACLs (setfacl) | Not supported | Not supported as POSIX.1e. NFSv4.1 volumes support NFSv4.x ACLs |
| Identity | Numeric uid and gid from the client (AUTH_SYS); no Kerberos for NFS shares | AUTH_SYS, or Kerberos with LDAP (Active Directory) for NFSv4.1 |
| Network access | Private endpoint or service endpoint; no public access over the internet | Delegated subnet in a virtual network |
| Root squash | Share setting: Root Squash, All Squash, No Root Squash | Export policy rule setting per client rule |

Confirm the capability rows against current Microsoft documentation during
design; both services change between releases, and the ACL rows decide the
target.

## ACL mapping caveats

POSIX.1e ACLs, the model this project provisions on legacy hosts, do not
exist on either target as such:

1. **Azure Files NFS has no ACLs beyond mode bits.** Every named group entry
   must be collapsed into the owning group. A directory that grants
   `fs_fin_ro` read and `fs_fin_rw` write cannot be represented with one
   owning group; split it into two directories, or move write to an
   application tier. Run `AccessDiffer` before and after to prove that no
   identity gains access through the collapse.
2. **Azure NetApp Files with NFSv4.1 uses NFSv4.x ACLs.** These are allow and
   deny access control entries with different semantics from POSIX.1e:
   * There is no mask. Effective rights after migration may be wider than on
     the source where the source mask limited named entries. Compute the
     masked rights (`AclEntry.permissions().intersect(mask)`) and migrate
     those, not the raw entry.
   * Default ACLs become inheritance flags (file inherit, directory inherit).
     A default entry without a matching access entry, which POSIX allows,
     becomes an inherit only entry.
   * Order matters for deny entries. Generate allow entries only.
   * Principals are names in `user@domain` form resolved through the NFSv4 id
     mapping domain. A mismatched id mapping domain shows every owner as
     `nobody`, which IdentityIQ will then report as unowned paths.
3. **NFSv3 on Azure NetApp Files keeps mode bits only.** Treat it as the Azure
   Files case for ACL purposes.

## uid and gid consistency

AUTH_SYS trusts the numbers the client sends. Before migration:

* Reconcile uid and gid across every client that will mount the target. The
  `OrphanDetector` findings `UNOWNED_PATH` and `UNKNOWN_GROUP_OWNER` list the
  numeric owners with no account; resolve or reassign them first.
* Keep governed gids in the reserved range on every client. A gid collision
  on any client grants that client's group the share's access.
* Prefer a directory service (LDAP or Active Directory with RFC 2307
  attributes) as the single source for uid and gid, and feed it from
  IdentityIQ provisioning rather than local files.

## Squash settings

Set Root Squash on every share or export policy rule unless a named backup
or migration host needs root. The `NO_ROOT_SQUASH` finding should be empty for
the target before cut over, apart from documented exceptions with an expiry.

## Data movement

1. Freeze provisioning for the share in IdentityIQ (disable requestable flags
   on its ManagedAttributes) to stop new grants during the copy.
2. Capture a source `EvidenceBundle` for every governed identity and the
   share's `getfacl -R` output.
3. Copy content with a tool that preserves ownership and mode bits for NFS
   targets (for example rsync with numeric ids, or Azure migration tooling
   for NetApp). Do not rely on a tool to translate ACLs; apply the access
   model separately from the mapping above.
4. Apply the mapped access model to the target, aggregate the target
   inventory into a new IdentityIQ application, and capture a target
   `EvidenceBundle`.
5. Compare the two bundles. Any EXCESS on the target blocks cut over.
6. Repoint the ManagedAttributes (`fsgovPath`) and the roles to the new
   application, run a targeted certification on the migrated share, then
   decommission the legacy export.

## Provisioning after migration

The change planner remains valid for mode bits and group membership.
For NFSv4.x ACL targets, add a planner that emits NFSv4 ACE steps; the
codec and evidence model are designed to extend with new step kinds without
changing the queue contract for existing ones.
