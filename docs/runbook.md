# Runbook

All commands are shown as console sessions. `$` denotes the prompt.

## Build and test

```console
$ mvn -B verify
```

The default build compiles `fsgov-core`, runs its tests with a coverage gate
(line 85 percent, branch 70 percent), and runs the configuration checks. The
adapter builds only with the IdentityIQ jar installed; see
`src/fsgov-iiq-adapter/README.md`.

## Deploying configuration

The `config/` tree follows the SSB layout. Copy it into the SSB `config`
directory, set the environment, and build.

```console
$ cp sandbox.target.properties /opt/ssb/sandbox.target.properties
$ cd /opt/ssb && ant -DSPTARGET=sandbox clean war
```

Import order for a first install (`iiq console` then `import <file>`):

1. `Configuration/ConnectorRegistry-FSGov.xml`
2. `Rule/` (the library first, then the rest)
3. `Application/`
4. `ManagedAttribute/`
5. `Bundle/`, `Policy/`
6. `Workflow/`, `CertificationDefinition/`
7. `TaskDefinition/`, `TaskSchedule/`

## Scheduled operations

| Order | Task | When |
|---|---|---|
| 1 | FSGov HR Aggregation | Nightly, after the HR drop |
| 2 | FSGov Filesystem Group Aggregation | After collector run |
| 3 | FSGov Filesystem Account Aggregation | After group aggregation |
| 4 | FSGov Identity Refresh | After aggregation |

Group aggregation must precede account aggregation so new groups exist as
ManagedAttributes before memberships correlate.

## Certification generation

`TaskSchedule/TaskSchedule-FSGov-Certifications.xml` schedules both
campaigns through the Certification Manager executor. If the target release
expects the definition id rather than its name in
`certificationDefinitionId`, look up the id after import and update the
schedule:

```console
$ iiq console
> get CertificationDefinition "FSGov Targeted File Share Entitlement Review"
```

## Change queue

| Symptom | Check | Action |
|---|---|---|
| Requests stay QUEUED | Files accumulating in the queue directory | Executor stopped or lacks permission; restart it and check its log. |
| Request FAILED with GID_CONFLICT | `getent group <gid>` on the host | Allocate a new gid on the ManagedAttribute; never reuse the old one. |
| Request FAILED with ACCOUNT_NOT_FOUND | Account in passwd inventory | Account not yet created by the platform process, or collector stale. |
| ACL_NOT_SUPPORTED warning | `/proc/mounts` options for the path | Add `acl` to the mount options for ext3 and legacy ext4, remount in a change window. |
| RESIDUAL_ACCESS warning | Nested group named in the warning | Revoke the nested path or record an approved exception. |

## Verifying a revocation

1. Wait for the next collector run and account aggregation.
2. Run an evidence diff for the identity and share (the adapter exposes it
   through the connector inventory; offline, load the inventory into
   `AccessDiffer`).
3. EXCESS must be empty for the revoked pair. Attach the bundle digest to the
   certification item comments.

## JBoss EAP 7.4

See `deploy/jboss-eap7/README.md` for first time setup. Routine checks:

```console
$ $JBOSS_HOME/bin/jboss-cli.sh --connect --command="/subsystem=datasources/data-source=IdentityIQDS:test-connection-in-pool"
$ $JBOSS_HOME/bin/jboss-cli.sh --connect --command="/subsystem=datasources/data-source=IdentityIQDS/statistics=pool:read-resource(include-runtime=true)"
```

## Rotating secrets

Database password or Entra client secret:

```console
$ $JBOSS_HOME/bin/jboss-cli.sh --connect --command="/subsystem=elytron/credential-store=iiq-store:set-secret(alias=iiq-db, secret-value=NEW_VALUE_FROM_VAULT)"
$ $JBOSS_HOME/bin/jboss-cli.sh --connect --command=":reload"
```

Clear the shell history afterwards, or enter the command in an interactive
CLI session so the value does not reach the history file.
