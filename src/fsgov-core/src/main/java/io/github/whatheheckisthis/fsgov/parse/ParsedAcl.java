package io.github.whatheheckisthis.fsgov.parse;

import io.github.whatheheckisthis.fsgov.model.Acl;

/** One file block from {@code getfacl -R --absolute-names} output. */
public record ParsedAcl(String path, String owner, String group, String flags, Acl acl) {
}
