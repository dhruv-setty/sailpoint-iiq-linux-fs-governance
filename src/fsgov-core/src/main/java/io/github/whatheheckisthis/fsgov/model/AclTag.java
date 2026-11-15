package io.github.whatheheckisthis.fsgov.model;

/** POSIX.1e ACL entry tag types, named as getfacl prints them. */
public enum AclTag {
    USER_OBJ("user", false),
    USER("user", true),
    GROUP_OBJ("group", false),
    GROUP("group", true),
    MASK("mask", false),
    OTHER("other", false);

    private final String keyword;
    private final boolean named;

    AclTag(String keyword, boolean named) {
        this.keyword = keyword;
        this.named = named;
    }

    public String keyword() {
        return keyword;
    }

    /** True for entries that carry a user or group qualifier. */
    public boolean isNamed() {
        return named;
    }

    /** True for entries whose effective rights are limited by the mask. */
    public boolean isMaskedClass() {
        return this == USER || this == GROUP || this == GROUP_OBJ;
    }

    public static AclTag of(String keyword, boolean hasQualifier) {
        switch (keyword) {
            case "user":
            case "u":
                return hasQualifier ? USER : USER_OBJ;
            case "group":
            case "g":
                return hasQualifier ? GROUP : GROUP_OBJ;
            case "mask":
            case "m":
                return MASK;
            case "other":
            case "o":
                return OTHER;
            default:
                throw new IllegalArgumentException("Unknown ACL tag: " + keyword);
        }
    }
}
