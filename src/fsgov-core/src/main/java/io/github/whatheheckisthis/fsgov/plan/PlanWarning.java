package io.github.whatheheckisthis.fsgov.plan;

/** A condition found while planning that a reviewer or the provisioning result must see. */
public record PlanWarning(Code code, String account, String detail) {

    /** Warning categories. */
    public enum Code {
        ACCOUNT_NOT_FOUND,
        UNKNOWN_ENTITLEMENT,
        PATH_NOT_FOUND,
        GID_CONFLICT,
        ACL_NOT_SUPPORTED,
        RESIDUAL_ACCESS,
        CONFLICTING_REQUESTS
    }
}
