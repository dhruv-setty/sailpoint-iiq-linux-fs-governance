# Running IdentityIQ on JBoss EAP 7.4 and WildFly

Notes and configuration for hosting the IdentityIQ web application on JBoss
EAP 7.4 or a WildFly release built on the same Java EE 8 platform. Confirm the
pairing of IdentityIQ release, application server and JDK against the
SailPoint support matrix before building an environment.

## Namespace: javax and jakarta

| Platform | Specification | Servlet and API namespace | Suitable for this IdentityIQ release |
|---|---|---|---|
| JBoss EAP 7.4 | Java EE 8 (and Jakarta EE 8, which kept `javax`) | `javax.*` | Yes |
| WildFly 26 and earlier | Java EE 8 / Jakarta EE 8 | `javax.*` | Yes, subject to the support matrix |
| JBoss EAP 8 | Jakarta EE 10 | `jakarta.*` | No |
| WildFly 27 and later | Jakarta EE 10 | `jakarta.*` | No |

IdentityIQ 8.4 is compiled against `javax.servlet`, `javax.ws.rs` and related
`javax` APIs. A Jakarta EE 10 server cannot load it without bytecode
transformation, which SailPoint does not support. The SSO rule in this
project references `javax.servlet.http.HttpServletRequest` for the same
reason.

## Extensions and subsystems used

| Subsystem | Use |
|---|---|
| `datasources` | Optional container datasource `java:jboss/datasources/IdentityIQDS`. |
| `elytron` | Credential store for the database password and the OIDC client secret. |
| `elytron-oidc-client` | OIDC sign in with Microsoft Entra ID. Present in WildFly 25 and later and in later JBoss EAP 7.4 update releases; check before use. |
| `undertow` | Session cookie flags, proxy forwarding behind the load balancer, HSTS. |
| `logging` | Separate `fsgov.log` for connector and rule logging. |
| `transactions`, `naming`, `ee` | Defaults. |

Subsystems excluded from the deployment (see
`snippets/jboss-deployment-structure.xml`): `jaxrs`, `jpa`, `weld`, `logging`.
IdentityIQ bundles its own Jersey, Hibernate, Spring and logging; letting the
container add its own implementations causes class loading conflicts.

## Database connection

IdentityIQ manages its own connection pool from `iiq.properties` by default,
and that remains the reference configuration. The container datasource here
is for sites whose platform standard requires container managed pools and
credential stores. Pointing IdentityIQ at a JNDI datasource is done through
the Spring data source configuration referenced by `iiq.properties`; follow
the SailPoint installation guide for the property names in the release in
use.

## First time setup

```console
$ cp deploy/jboss-eap7/local.properties.example deploy/jboss-eap7/local.properties
$ $JBOSS_HOME/bin/elytron-tool.sh mask --salt 12345678 --iteration 230 --secret "store password"
$ $JBOSS_HOME/bin/jboss-cli.sh --connect --file=deploy/jboss-eap7/cli/01-jdbc-driver.cli --properties=deploy/jboss-eap7/local.properties
$ $JBOSS_HOME/bin/jboss-cli.sh --connect --file=deploy/jboss-eap7/cli/02-credential-store.cli --properties=deploy/jboss-eap7/local.properties
$ $JBOSS_HOME/bin/jboss-cli.sh --connect --file=deploy/jboss-eap7/cli/03-datasource.cli --properties=deploy/jboss-eap7/local.properties
$ $JBOSS_HOME/bin/jboss-cli.sh --connect --file=deploy/jboss-eap7/cli/04-undertow-hardening.cli
$ $JBOSS_HOME/bin/jboss-cli.sh --connect --file=deploy/jboss-eap7/cli/06-logging.cli
```

Put the masked value printed by `elytron-tool` into `local.properties` as
`credential.store.masked.password`. Delete `local.properties` once the store
is created.

Deploy IdentityIQ exploded so `iiq.properties` and logging configuration can
be maintained in place:

```console
$ cp -r build/extract/identityiq.war $JBOSS_HOME/standalone/deployments/identityiq.war
$ cp deploy/jboss-eap7/snippets/jboss-deployment-structure.xml $JBOSS_HOME/standalone/deployments/identityiq.war/WEB-INF/
$ touch $JBOSS_HOME/standalone/deployments/identityiq.war.dodeploy
```

## Sign in with Microsoft Entra ID

Two supported shapes exist; choose one.

1. **IdentityIQ native SAML SSO** with an Entra ID enterprise application.
   No container configuration is needed. This is the simpler path and the
   recommended default.
2. **Container OIDC** with `elytron-oidc-client`, for sites that standardise on
   OIDC at the application server. `cli/05-elytron-oidc.cli` configures the
   provider and secure deployment; `snippets/standalone-elytron-oidc.xml` shows
   the result. The container authenticates; the `FSGov-SSOAuthentication`
   rule maps `preferred_username` to an active identity by email and is
   selected under Global Settings, Login Configuration, SSO Configuration.

Entra ID application registration for option 2:

* Platform: Web. Redirect URI: `https://<iiq-host>/identityiq/` as the
  subsystem builds it; confirm the exact callback path on first sign in.
* Token configuration: include `preferred_username` and `email`.
* Client secret or certificate stored only in the Elytron credential store.
* Assign users and groups to the enterprise application so only intended
  staff can obtain a token.

Keep a local break glass administrator and test that the standard login page
remains reachable when the rule returns no identity. API clients
(`/identityiq/rest`, `/identityiq/scim`) should use their own OAuth client
credentials in IdentityIQ, not browser OIDC; exclude these paths from the
secured deployment where the patch level allows path based constraints.

## Files

| File | Purpose |
|---|---|
| `cli/01-jdbc-driver.cli` | JDBC module and driver registration |
| `cli/02-credential-store.cli` | Elytron credential store and aliases |
| `cli/03-datasource.cli` | Datasource with validation and credential reference |
| `cli/04-undertow-hardening.cli` | Cookie flags, timeouts, proxy and headers |
| `cli/05-elytron-oidc.cli` | OIDC with Entra ID |
| `cli/06-logging.cli` | fsgov log handler |
| `modules/com/microsoft/sqlserver/main/module.xml` | JDBC driver module definition |
| `snippets/*.xml` | Resulting `standalone.xml` fragments and the deployment structure descriptor |
| `local.properties.example` | Template for host only values, never committed filled in |
