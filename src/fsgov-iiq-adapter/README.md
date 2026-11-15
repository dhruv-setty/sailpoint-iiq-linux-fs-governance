# fsgov-iiq-adapter

IdentityIQ custom connector (`LegacyFilesystemConnector`) that delegates change
planning to `fsgov-core`. It compiles against `identityiq.jar`, which SailPoint
licenses to customers and which is not available from any public repository,
so this module is excluded from default builds and from CI.

## Building

Install the jar from the customer's IdentityIQ distribution
(`WEB-INF/lib/identityiq.jar`) into the local Maven repository, then build with
the `iiq` profile. The profile also activates by itself once the jar is present.

```console
$ mvn install:install-file -Dfile=/path/to/identityiq.jar -DgroupId=sailpoint -DartifactId=identityiq -Dversion=8.4 -Dpackaging=jar
$ mvn -Piiq verify
```

Copy `fsgov-core` and `fsgov-iiq-adapter` jars into `WEB-INF/lib` of the
IdentityIQ web application (or the SSB `web/WEB-INF/lib` overlay).

## Status

The connector has not been compiled or run against a real IdentityIQ instance
in this repository. Method signatures follow the documented `AbstractConnector`
contract; confirm them against the `identityiq.jar` in use.
