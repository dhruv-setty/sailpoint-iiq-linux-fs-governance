package io.github.whatheheckisthis.fsgov.iiq;

import io.github.whatheheckisthis.fsgov.model.EntitlementCatalog;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;
import io.github.whatheheckisthis.fsgov.model.ShareEntitlement;
import sailpoint.api.SailPointContext;
import sailpoint.api.SailPointFactory;
import sailpoint.object.Application;
import sailpoint.object.Filter;
import sailpoint.object.ManagedAttribute;
import sailpoint.object.QueryOptions;
import sailpoint.tools.GeneralException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds the fsgov entitlement catalog from the ManagedAttribute objects of
 * the application, using the fsgovPath, fsgovGid, fsgovPermissions and
 * fsgovInherit extended attributes.
 */
final class CatalogLoader {

    private final Application application;

    CatalogLoader(Application application) {
        this.application = application;
    }

    EntitlementCatalog load() throws IOException {
        try {
            SailPointContext ctx = SailPointFactory.getCurrentContext();
            QueryOptions qo = new QueryOptions();
            qo.addFilter(Filter.eq("application.id", application.getId()));
            qo.addFilter(Filter.eq("attribute", "groups"));
            List<ShareEntitlement> out = new ArrayList<>();
            for (ManagedAttribute ma : ctx.getObjects(ManagedAttribute.class, qo)) {
                Object path = ma.getAttribute("fsgovPath");
                Object gid = ma.getAttribute("fsgovGid");
                Object perms = ma.getAttribute("fsgovPermissions");
                if (path == null || gid == null || perms == null) {
                    continue;
                }
                out.add(new ShareEntitlement(ma.getValue(), Integer.parseInt(gid.toString()), path.toString(),
                        PermissionSet.parse(perms.toString()),
                        Boolean.parseBoolean(String.valueOf(ma.getAttribute("fsgovInherit"))),
                        ma.getOwner() == null ? null : ma.getOwner().getName()));
            }
            return new EntitlementCatalog(out);
        } catch (GeneralException e) {
            throw new IOException("Cannot load entitlement catalog: " + e.getMessage(), e);
        }
    }
}
