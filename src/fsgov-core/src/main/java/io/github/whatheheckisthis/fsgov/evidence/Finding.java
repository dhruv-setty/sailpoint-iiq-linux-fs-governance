package io.github.whatheheckisthis.fsgov.evidence;

/** One hygiene finding. {@code subject} is the uid, gid, group or client it concerns. */
public record Finding(FindingType type, String path, String subject, String detail) {
}
