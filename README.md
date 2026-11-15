# IdentityIQ Legacy Filesystem Governance

SailPoint IdentityIQ project for governing legacy Linux file systems: POSIX
and ACL provisioning, access certification, and JBoss EAP 7 deployment.

Legacy file servers (ext3, ext4, XFS, published over NFSv3) hold regulated
records but express access in owner, group and mode bits, POSIX.1e ACLs and
export options that drift through manual change. This project brings that
access under IdentityIQ: requests with approval, provisioning through an
ordered and idempotent change plan, separation of duties between finance and
audit write access, targeted and manager certifications, and evidence that a
revocation actually took effect on disk.

## Repository layout

```text
config/                    IdentityIQ XML artifacts (SSB layout, %%TOKEN%% placeholders)
  Application/             HR delimited authoritative source, legacy Linux file system
  Rule/                    BuildMap, Correlation, Before and After Provisioning,
                           Certification exclusion, remediation evidence, SSO, library
  CertificationDefinition/ Targeted file share review, manager review
  Workflow/                Access request approval
  TaskDefinition/          Aggregation and identity refresh
  TaskSchedule/            Certification generation
  Policy/                  SoD: finance share write vs audit share write
  Bundle/                  IT and business roles
  ManagedAttribute/        Entitlement catalog with share bindings
  Configuration/           Connector registry entry
sandbox.target.properties  Token values for the sandbox environment
src/
  fsgov-core/              Pure Java model, change planner, evidence (JUnit 5)
  fsgov-config-validation/ Build checks over config/ and deploy/
  fsgov-iiq-adapter/       IdentityIQ custom connector (Maven profile iiq)
  OntapNfs/                .NET 8: ONTAP NFSv3 file access, REST orchestration, WAR deploy
deploy/jboss-eap7/         JBoss EAP 7.4 notes, CLI scripts, module and snippets
docs/                      Architecture, provisioning, certification, cloud migration,
                           ONTAP NFSv3, runbook, security policy
```

## Build

Requires a JDK 17 or later and Maven.

```console
$ mvn -B verify
```

The default build runs the core unit tests with a coverage gate and parses
every XML file under `config/` and `deploy/`, checks that each IdentityIQ
artifact declares the `sailpoint.dtd` DOCTYPE, that every object reference and
rule name resolves, that every `%%TOKEN%%` has a value, and that the
repository contains no script sources.

The IdentityIQ adapter needs the licensed `identityiq.jar`:

```console
$ mvn install:install-file -Dfile=identityiq.jar -DgroupId=sailpoint -DartifactId=identityiq -Dversion=8.4 -Dpackaging=jar
$ mvn -B -Piiq verify
```

## ONTAP NFSv3 module (C#)

`src/OntapNfs` is a .NET 8 solution for NetApp ONTAP storage published over
NFSv3 to the application hosts this project governs. It runs beside
IdentityIQ as operations tooling and shares no code with the Java modules.

* `OntapNfs.Core`: System.IO access to a mounted share (`/mnt/ontap/vol1`,
  `N:\` or a UNC path) with explicit `FileShare` modes, retry with backoff on
  stale handles and lock contention, atomic write by temporary file and
  rename, and a path guard against traversal. A model of ONTAP export policy
  rules (clientmatch, rorule, rwrule, superuser, anon, root squash) and a
  validator that checks a service account maps to a valid UID and GID the
  export allows.
* `OntapNfs.Ontap`: typed ONTAP REST client (volumes, export policies and
  rules, unix users and groups, NFS services, job polling) with idempotent
  ensure operations. Credentials come from `ONTAP_BASE_URL`,
  `ONTAP_USERNAME` and `ONTAP_PASSWORD`.
* `OntapNfs.Deploy`: atomic WAR deployment to Tomcat, WildFly (marker files)
  and Jetty deployment directories on the share.

```text
dotnet test src/OntapNfs/OntapNfs.sln -c Release
```

Design, the ONTAP native and SAN re-export paths, UID and GID mapping,
locking and the link to the IdentityIQ provisioning model are in
[docs/ontap-nfsv3.md](docs/ontap-nfsv3.md).

## How a grant becomes a change on disk

```java
ChangePlan plan = new ChangePlanner(catalog).plan(snapshot,
        List.of(ProvisioningRequest.addGroup("alice", "fs_fin_rw")));
plan.describe();
// groupadd -g 4101 fs_fin_rw
// setfacl -n -m default:group:fs_fin_rw:rwx /srv/finance
// setfacl -n -m group:fs_fin_rw:rwx /srv/finance
// setfacl -n -m mask::rwx /srv/finance
// setfacl -n -m default:mask::rwx /srv/finance
// gpasswd -a alice fs_fin_rw
```

The lines above are a display form for reviewers. The connector queues the
structured steps (`ChangePlanCodec`), and the host executor applies them; no
command text is executed anywhere in this project.

## Documentation

* [Architecture](docs/architecture.md)
* [Legacy file system provisioning design](docs/legacy-filesystem-provisioning.md)
* [Access certification design](docs/access-certification.md)
* [Cloud migration notes](docs/cloud-migration.md)
* [ONTAP NFSv3 module](docs/ontap-nfsv3.md)
* [Runbook](docs/runbook.md)
* [JBoss EAP 7 deployment](deploy/jboss-eap7/README.md)
* [Security policy](docs/SECURITY.md)

## Verification status

* `fsgov-core` and the configuration checks run in CI on every push.
* The ONTAP NFSv3 module's unit tests run in CI in a separate `dotnet` job.
  The REST client is tested against a fake HTTP handler and file access
  against local temporary directories; it has not run against a real ONTAP
  cluster, a real NFSv3 mount or a running application server.
* The IdentityIQ artifacts are checked for well formedness and internal
  consistency only. `sailpoint.dtd` is not public, so they have not been
  validated against it, and none of them has been imported into a running
  IdentityIQ instance.
* The adapter has not been compiled against `identityiq.jar` in CI.
* The JBoss CLI scripts have not been run against a server in CI.

Treat the configuration as a reviewed starting point for an implementation,
to be imported and tested in a sandbox before any higher environment.

## License

MIT. See [LICENSE](LICENSE).
