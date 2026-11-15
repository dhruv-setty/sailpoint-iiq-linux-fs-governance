package io.github.whatheheckisthis.fsgov.iiq;

import io.github.whatheheckisthis.fsgov.model.EntitlementCatalog;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.plan.ChangePlan;
import io.github.whatheheckisthis.fsgov.plan.ChangePlanCodec;
import io.github.whatheheckisthis.fsgov.plan.ChangePlanner;
import io.github.whatheheckisthis.fsgov.plan.PlanWarning;
import io.github.whatheheckisthis.fsgov.plan.ProvisioningRequest;
import sailpoint.connector.AbstractConnector;
import sailpoint.connector.ConnectorException;
import sailpoint.object.Application;
import sailpoint.object.Filter;
import sailpoint.object.ProvisioningPlan;
import sailpoint.object.ProvisioningPlan.AccountRequest;
import sailpoint.object.ProvisioningResult;
import sailpoint.object.ResourceObject;
import sailpoint.object.Schema;
import sailpoint.tools.CloseableIterator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * IdentityIQ custom connector for legacy Linux file servers.
 *
 * <p>Aggregation reads the inventory written by the host collector. Provisioning
 * converts each AccountRequest into an fsgov {@link ChangePlan} and writes it,
 * encoded by {@link ChangePlanCodec}, to the change queue directory, where the
 * host executor picks it up and applies the structured steps. The connector never opens a
 * shell to the host and never executes command text. The result is QUEUED;
 * the next aggregation confirms the change, which is the verification half of
 * the closed loop.</p>
 *
 * <p>Built only with the {@code iiq} Maven profile against a locally installed
 * identityiq.jar. Not exercised against a running IdentityIQ instance in this
 * repository.</p>
 */
public class LegacyFilesystemConnector extends AbstractConnector {

    public static final String CONNECTOR_TYPE = "FSGov Legacy Linux Filesystem";

    private final InventoryReader inventory;
    private final CatalogLoader catalogLoader;

    public LegacyFilesystemConnector(Application application) {
        super(application);
        this.inventory = new InventoryReader(Path.of(application.getStringAttributeValue("inventoryDirectory")));
        this.catalogLoader = new CatalogLoader(application);
    }

    @Override
    public String getConnectorType() {
        return CONNECTOR_TYPE;
    }

    @Override
    public void testConfiguration() throws ConnectorException {
        for (String key : new String[] {"inventoryDirectory", "changeQueueDirectory"}) {
            String dir = getApplication().getStringAttributeValue(key);
            if (dir == null || !Files.isDirectory(Path.of(dir))) {
                throw new ConnectorException(key + " is not a readable directory: " + dir);
            }
        }
    }

    @Override
    public CloseableIterator<ResourceObject> iterateObjects(String objectType, Filter filter, Map<String, Object> options)
            throws ConnectorException {
        Schema schema = getApplication().getSchema(objectType);
        try {
            return inventory.iterate(objectType, schema);
        } catch (IOException e) {
            throw new ConnectorException("Cannot read inventory for " + objectType + ": " + e.getMessage(), e);
        }
    }

    @Override
    public ResourceObject getObject(String objectType, String identity, Map<String, Object> options)
            throws ConnectorException {
        try {
            return inventory.find(objectType, getApplication().getSchema(objectType), identity);
        } catch (IOException e) {
            throw new ConnectorException("Cannot read inventory for " + identity + ": " + e.getMessage(), e);
        }
    }

    @Override
    public ProvisioningResult provision(ProvisioningPlan plan) throws ConnectorException {
        ProvisioningResult overall = new ProvisioningResult();
        overall.setStatus(ProvisioningResult.STATUS_QUEUED);
        FilesystemSnapshot snapshot;
        EntitlementCatalog catalog;
        try {
            snapshot = inventory.snapshot();
            catalog = catalogLoader.load();
        } catch (IOException e) {
            throw new ConnectorException("Cannot build snapshot: " + e.getMessage(), e);
        }
        ChangePlanner planner = new ChangePlanner(catalog);
        PlanTranslator translator = new PlanTranslator();
        for (AccountRequest req : plan.getAccountRequests()) {
            ProvisioningResult r = new ProvisioningResult();
            try {
                List<ProvisioningRequest> requests = translator.translate(req);
                ChangePlan changes = planner.plan(snapshot, requests);
                List<String> lines = changes.describe();
                r.setStatus(changes.isNoOp() ? ProvisioningResult.STATUS_COMMITTED : ProvisioningResult.STATUS_QUEUED);
                r.addAttribute("fsgovChangePlan", lines);
                r.addAttribute("fsgovPlanDigest", digest(lines));
                r.addAttribute("fsgovWarnings", changes.warnings().stream()
                        .map(w -> w.code() + ": " + w.detail()).toList());
                if (changes.hasWarning(PlanWarning.Code.ACCOUNT_NOT_FOUND)
                        || changes.hasWarning(PlanWarning.Code.GID_CONFLICT)) {
                    r.setStatus(ProvisioningResult.STATUS_FAILED);
                    r.addError("fsgov planning refused the request; see fsgovWarnings");
                } else if (!changes.isNoOp()) {
                    enqueue(req.getNativeIdentity(), changes);
                }
            } catch (IllegalArgumentException | IOException e) {
                r.setStatus(ProvisioningResult.STATUS_FAILED);
                r.addError(e.getMessage());
            }
            req.setResult(r);
        }
        return overall;
    }

    private void enqueue(String account, ChangePlan changes) throws IOException {
        Path dir = Path.of(getApplication().getStringAttributeValue("changeQueueDirectory"));
        String encoded = new ChangePlanCodec().encode(changes.steps());
        String name = "fsgov-" + account + "-" + digest(List.of(encoded)).substring(0, 16) + ".plan";
        if (Files.exists(dir.resolve(name))) {
            return; // identical plan already queued: the name is derived from the content
        }
        Path tmp = dir.resolve(name + ".tmp");
        Files.writeString(tmp, encoded, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.move(tmp, dir.resolve(name), java.nio.file.StandardCopyOption.ATOMIC_MOVE);
    }

    static String digest(List<String> lines) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(String.join("\n", lines).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
