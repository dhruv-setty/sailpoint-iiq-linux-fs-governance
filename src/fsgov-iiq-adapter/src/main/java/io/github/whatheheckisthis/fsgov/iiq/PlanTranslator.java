package io.github.whatheheckisthis.fsgov.iiq;

import io.github.whatheheckisthis.fsgov.plan.Operation;
import io.github.whatheheckisthis.fsgov.plan.ProvisioningRequest;
import sailpoint.object.ProvisioningPlan;
import sailpoint.object.ProvisioningPlan.AccountRequest;
import sailpoint.object.ProvisioningPlan.AttributeRequest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Converts one IdentityIQ {@link AccountRequest} into fsgov-core requests.
 * Only Add and Remove of the {@code groups} and {@code directPermissions}
 * attributes are supported; Set is expanded by the caller against the
 * current link before translation, and any other attribute is rejected so a
 * silent no-op can never be reported as success.
 */
public final class PlanTranslator {

    public List<ProvisioningRequest> translate(AccountRequest request) {
        List<ProvisioningRequest> out = new ArrayList<>();
        if (request.getAttributeRequests() == null) {
            return out;
        }
        String account = request.getNativeIdentity();
        for (AttributeRequest ar : request.getAttributeRequests()) {
            String name = ar.getName();
            if (!ProvisioningRequest.ATTR_GROUPS.equals(name)
                    && !ProvisioningRequest.ATTR_DIRECT_PERMISSIONS.equals(name)) {
                throw new IllegalArgumentException("Unsupported attribute for legacy file system: " + name);
            }
            Operation op = toOperation(ar.getOperation());
            for (String value : values(ar.getValue())) {
                out.add(new ProvisioningRequest(account, op, name, value));
            }
        }
        return out;
    }

    static Operation toOperation(ProvisioningPlan.Operation op) {
        if (op == ProvisioningPlan.Operation.Add) {
            return Operation.ADD;
        }
        if (op == ProvisioningPlan.Operation.Remove || op == ProvisioningPlan.Operation.Revoke) {
            return Operation.REMOVE;
        }
        throw new IllegalArgumentException("Unsupported operation: " + op);
    }

    static List<String> values(Object value) {
        List<String> out = new ArrayList<>();
        if (value instanceof Collection<?> c) {
            for (Object o : c) {
                if (o != null) {
                    out.add(o.toString());
                }
            }
        } else if (value != null) {
            out.add(value.toString());
        }
        return out;
    }
}
