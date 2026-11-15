# Access Certification Design

## Campaign types

| Campaign | Definition | Reviewer | Cadence | Purpose |
|---|---|---|---|---|
| Targeted file share review | `FSGov Targeted File Share Entitlement Review` (Focused) | Entitlement owner of each share group, manager as fallback | Quarterly | Confirms that the content warrants the access. |
| Manager access review | `FSGov Manager Access Review` (Manager) | Line manager | Semi annual | Confirms that the person still needs the access. |
| SoD violations | Included in both | Violation owner (manager) | With each campaign | Forces a decision on finance write combined with audit write. |

Service identities are excluded by `FSGov-CertificationExclusion` and are
reviewed by their owners in a separate service account campaign. Items for
groups outside the governed catalog are excluded with an explanation and
tracked by the orphan report instead, because the targeted campaign cannot
remediate them.

## What a reviewer sees

Each item is one governed group or one direct ACL entry on one account. The
item description comes from the ManagedAttribute (share path and access
level). Evidence from `AccessDiffer` is attached to the campaign so a
reviewer can see effective access, which may differ from the entitlement:

| Status | Meaning | Typical cause |
|---|---|---|
| MATCH | Effective access equals the identity model | Normal |
| EXCESS | Host grants more than IdentityIQ asserts | Manual setfacl, nested group, owner or other bits |
| MISSING | IdentityIQ asserts access the host does not grant | Restrictive mask, ro export, unqueued change |
| DIVERGENT | Both | Drift in both directions |

Each record carries the ACL entry or rule that explains the actual value,
for example `group:fs_fin_ro:r-x masked by r-x` or `superuser after
root_squash`.

## Revocation closed loop

1. A reviewer revokes an item. `processRevokesImmediately` is set, so
   IdentityIQ creates a Remove request at sign off rather than at campaign
   end.
2. `FSGov-BeforeProvisioning` orders the request; the connector plans and
   queues the change. The AfterProvisioning rule logs the plan text and its
   SHA-256 digest (`fsgovProvisioning` audit event).
3. On entry to the Remediation and End phases, `FSGov-Remediation-Evidence`
   logs one `fsgovRevocationDecision` event per revoked item with reviewer,
   decision time and comments.
4. The host executor applies the plan. The next account aggregation
   (`noOptimizeReaggregation` is on) updates the link.
5. Verification: an `AccessDiffer` run over the revoked pairs must show no
   EXCESS. A remaining EXCESS is escalated to the share owner with its source
   line, which usually names the nested group or direct entry still granting
   access.
6. The campaign is not signed off as remediated until verification passes;
   the remediation period (seven days) bounds the wait.

## Evidence package

For each campaign the evidence package contains:

* The campaign report exported from IdentityIQ.
* The `EvidenceBundle` captured at campaign generation and after
  remediation, each with its SHA-256 digest over the canonical text. The
  canonical form is sorted and tab separated, so anyone can recompute the
  digest from the same snapshot.
* The `fsgovProvisioning` and `fsgovRevocationDecision` audit events.
* The hygiene findings from `OrphanDetector` (unowned paths, dangling ACL
  entries, empty governed groups, world writable paths, `no_root_squash`
  exports, ungoverned paths) with their disposition.

## Limits

* Effective access is computed from the collector snapshot. Changes made on
  the host after collection are not visible until the next collection.
* For the group class, evidence reports the union of bits obtainable through
  any one matching group entry. POSIX grants a request only if a single entry
  holds all requested bits, so a request needing bits from two different
  groups may be denied even though each bit is listed.
* Access through applications that run as a privileged service account is
  not attributed to end users.
