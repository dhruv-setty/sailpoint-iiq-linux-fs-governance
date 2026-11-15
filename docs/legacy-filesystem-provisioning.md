# Legacy File System Provisioning Design

## Target estate

| File system | ACL availability | Notes |
|---|---|---|
| ext3 | Requires the `acl` mount option on older distributions | Verify `/proc/mounts` on every host; a missing option makes setfacl fail with "Operation not supported". |
| ext4 | Enabled by default on current kernels | Legacy `fstab` entries may still carry `noacl`. |
| XFS | Always available | No mount option required. |
| NFSv3 client mounts | Through the NFSACL side band protocol | NFSv3 itself carries no ACLs. The server applies its own ACLs; clients see effective rights only if NFSACL is enabled on both sides. |

The collector records the ACL capability of each governed path in
`paths.tsv`. The planner refuses to bind a group on a path where ACLs are not
enabled (warning `ACL_NOT_SUPPORTED`) rather than fall back to changing the
owning group or mode, which would alter access for everyone on the share.

## Entitlement model

* `groups`: a governed POSIX group. The ManagedAttribute carries
  `fsgovPath`, `fsgovGid`, `fsgovPermissions` and `fsgovInherit`.
* `directPermissions`: a named user ACL entry, `<path>:<rwx>`. Exception use.

Group ids for governed groups are allocated from a reserved range
(`minimumManagedGid` to `maximumManagedGid` on the application). A gid already
used by another group stops the plan with `GID_CONFLICT`; it is never reused,
because files created under the old group would silently become accessible
to the new one.

## From provisioning plan to change plan

1. IdentityIQ compiles a `ProvisioningPlan`. The `FSGov-BeforeProvisioning`
   rule converts account Delete into removal of every governed group, drops
   values outside the catalog and orders Remove before Add.
2. The connector translates each `AccountRequest` into
   `ProvisioningRequest` objects (`PlanTranslator`). Unsupported attributes
   or operations fail the request; they are never ignored.
3. `ChangePlanner` evaluates the requests against a `FilesystemSnapshot`:
   * A request that is already satisfied produces no step and is listed in
     `alreadySatisfied`.
   * A grant and a revocation of the same access in one request list keep the
     revocation (`CONFLICTING_REQUESTS`). This is checked on the requests,
     before state is consulted, so an already satisfied revocation still
     suppresses the grant.
   * Removing a direct membership while the account still reaches the group
     through nesting raises `RESIDUAL_ACCESS`.
4. Steps are ordered by phase and then by a stable key:

| Phase | Step | Equivalent notation (display only) |
|---|---|---|
| REVOKE_ACL | RemoveAclEntry (default scope first) | `setfacl -n -x default:user:carol /srv/audit` |
| REVOKE_MEMBERSHIP | RemoveMembership | `gpasswd -d bob fs_fin_ro` |
| CREATE_GROUP | CreateGroup | `groupadd -g 4101 fs_fin_rw` |
| GRANT_ACL | SetAclEntry | `setfacl -n -m group:fs_fin_rw:rwx /srv/finance` |
| SET_MASK | SetMask | `setfacl -n -m mask::rwx /srv/finance` |
| GRANT_MEMBERSHIP | AddMembership | `gpasswd -a alice fs_fin_rw` |

   The notation column is rendered by `ChangeStep.equivalentCommand()` for
   reviewers and audit records. Nothing executes it.

5. The plan is encoded with `ChangePlanCodec` (`#fsgov-plan v1`, one tab
   separated step per line) and written atomically to the change queue. The
   file name is derived from the content, so a retried request does not queue
   a second copy.

## Idempotency

Every step states an end state (an entry with exact permissions, a membership
present or absent, a mask value). Applying a plan twice equals applying it
once, and planning again after applying yields an empty plan. Both
properties are covered by `ChangePlannerTest.replanningAfterApplyIsEmpty`.

## Default ACLs and the mask

* The first default entry on a directory makes setfacl copy the access base
  entries into the default scope. `AclOps.set` reproduces this so the
  predicted state matches the host.
* The mask is the union of the group class entries in each scope. Because a
  wider mask can widen the effective rights of entries that were previously
  masked, any `SetMask` that adds bits is visible in the plan and in the
  provisioning audit event.

## NFSv3 exports

Exports are parsed from `/etc/exports` (`ExportsParser`) and evaluated in
`AccessEvaluator`:

* `root_squash` (the default) maps uid 0 to `anonuid`, normally 65534.
* `all_squash` maps every user to the anonymous ids.
* `ro` (the default) removes write regardless of ACLs.
* `no_root_squash` is reported as a hygiene finding on every export.

Squashing is an export property, not an identity property. A governed group
grant does not help a squashed client, and a `no_root_squash` export lets
any root on that client bypass every ACL. Both appear in certification
evidence when the application's `nfsClientForEvidence` is set.

## Group nesting

Flat `/etc/group` cannot nest groups. Where a directory service resolves
nesting for the host (for example SSSD with LDAP), `GroupResolver` flattens
it, tolerates cycles and reports them (`NESTING_CYCLE`). The kernel sees only
the flattened list, and some legacy NSS stacks cap the number of
supplementary groups, so deep nesting is discouraged.
