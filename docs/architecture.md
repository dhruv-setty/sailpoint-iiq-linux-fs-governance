# Architecture

## Purpose

Legacy Linux file servers hold a large share of regulated business records:
ledgers, payment files, audit working papers. Access on these hosts is
expressed in POSIX owner, group and mode bits, POSIX.1e ACLs and NFSv3 export
options, and it drifts through manual change. This project places that
access under SailPoint IdentityIQ governance: request and approval,
provisioning, separation of duties, periodic certification and evidence that
revocations took effect.

## Components

| Component | Location | Role |
|---|---|---|
| IdentityIQ artifacts | `config/` | Applications, rules, workflow, certification definitions, tasks, policy and roles, deployed with the Services Standard Build (SSB) token model. |
| fsgov-core | `src/fsgov-core` | Pure Java model of file system access, change planning, evidence and hygiene detection. No IdentityIQ dependency; fully unit tested. |
| fsgov-iiq-adapter | `src/fsgov-iiq-adapter` | IdentityIQ custom connector that uses fsgov-core. Built only with the `iiq` profile. |
| Config validation | `src/fsgov-config-validation` | Build time checks that parse every XML artifact and verify cross references and repository policy. |
| JBoss deployment | `deploy/jboss-eap7` | Datasource, JDBC module, Elytron credential store, OIDC sign in and web tier settings for JBoss EAP 7.4. |
| Host collector and executor | Out of scope | Agents on each file server that export inventory and apply queued change steps. Their contract is defined here. |

## Data flow

```text
 HR extract ──► [HR Authoritative app] ──► Identity cube (manager, department, linuxLogin)
                                                │
 Host collector                                 ▼
  getent passwd/group ─┐               Identity Refresh ──► SoD policy, role detection
  getfacl -R           ├─► inventory ─► [Legacy Linux Filesystem app] ─► Links, entitlements
  /etc/exports         │                        ▲                             │
  paths.tsv           ─┘                        │                             ▼
                                                │        Access request ──► Approval workflow
                                                │        Certification revoke ─┐    │
                                                │                              ▼    ▼
                                                │                    ProvisioningPlan
                                                │                              │
                                                │                BeforeProvisioning rule
                                                │                              │
                                                │                 fsgov connector (fsgov-core)
                                                │                   ChangePlanner ─► ChangePlan
                                                │                              │
                                                │               change queue (fsgov-plan v1)
                                                │                              │
                                                └──── next aggregation ◄── host executor
```


## Key decisions

1. **Group based grants first.** Each share and access level is one governed
   POSIX group (`fs_<share>_<ro|rw>`) bound to the share by a named group ACL
   entry and, for directories, a default entry. Direct user ACL entries are
   supported as exceptions only, because they do not survive account
   renames and are difficult to certify at scale.
2. **Plan, then queue, then verify.** The connector computes a complete,
   ordered, idempotent change plan from a snapshot of the host and queues it.
   It never connects to the host interactively and never executes command
   text. Success in IdentityIQ is QUEUED until the next aggregation shows the
   access, which keeps the identity model honest about what is on disk.
3. **Revocation before grant.** A plan never holds both the old and new access
   at once, which matters for the finance and audit SoD policy.
4. **Explicit ACL masks.** The mask is computed and written as a step. Relying
   on setfacl to recalculate the mask on the host makes the outcome depend on
   the order of operations and on the setfacl build in use.
5. **Accounts are not deleted on legacy hosts.** Leavers lose all governed
   groups and direct entries; the POSIX account remains so file ownership by
   uid stays resolvable for audit. Account removal is a separate platform
   process outside this project.
6. **IdentityIQ is the catalog.** Share path, gid, permissions and inheritance
   for each group live as extended attributes on the ManagedAttribute, so the
   approver, the certifier and the connector all read the same definition.

## Trust boundaries

* IdentityIQ to change queue: the queue directory is writable only by the
  IdentityIQ service account and readable only by the executor. The codec
  rejects control characters, so a crafted name cannot add a step.
* Executor on the host: runs with the minimum privilege needed for
  `groupadd`, membership changes and `setfacl` on governed roots, and refuses
  steps outside the governed roots configured on the application.
* Browser to IdentityIQ: OIDC through Entra ID at the container, mapped to an
  identity by the SSO rule, with IdentityIQ authorisation unchanged.

## Package layout of fsgov-core

| Package | Contents |
|---|---|
| `model` | PermissionSet, PosixMode, AclEntry, Acl, PathEntry, Account, Group, NfsExport, FilesystemSnapshot, GroupResolver, AccessEvaluator, EntitlementCatalog |
| `plan` | ProvisioningRequest, ChangeStep, Phase, ChangePlanner, ChangePlan, PlanApplier, ChangePlanCodec |
| `evidence` | AccessDiffer, EvidenceRecord, EvidenceBundle, OrphanDetector, Finding |
| `parse` | GetfaclParser, ExportsParser |
