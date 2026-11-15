package io.github.whatheheckisthis.fsgov.parse;

import io.github.whatheheckisthis.fsgov.model.Acl;
import io.github.whatheheckisthis.fsgov.model.AclEntry;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses the text produced by {@code getfacl}, the format the inventory
 * collector on each legacy host exports for aggregation. Paths printed
 * without a leading slash (getfacl strips it unless {@code --absolute-names}
 * is given) are made absolute. Effective rights comments are ignored, because
 * they are recomputed from the mask.
 */
public final class GetfaclParser {

    public List<ParsedAcl> parse(String text) {
        List<ParsedAcl> out = new ArrayList<>();
        String path = null;
        String owner = "";
        String group = "";
        String flags = "";
        List<AclEntry> entries = new ArrayList<>();
        int lineNo = 0;
        for (String raw : text.split("\\R", -1)) {
            lineNo++;
            String line = raw.strip();
            if (line.isEmpty()) {
                if (path != null) {
                    out.add(new ParsedAcl(path, owner, group, flags, Acl.of(entries)));
                }
                path = null;
                owner = "";
                group = "";
                flags = "";
                entries = new ArrayList<>();
            } else if (line.startsWith("# file:")) {
                String p = line.substring("# file:".length()).strip();
                path = p.startsWith("/") ? p : "/" + p;
            } else if (line.startsWith("# owner:")) {
                owner = line.substring("# owner:".length()).strip();
            } else if (line.startsWith("# group:")) {
                group = line.substring("# group:".length()).strip();
            } else if (line.startsWith("# flags:")) {
                flags = line.substring("# flags:".length()).strip();
            } else if (line.startsWith("#")) {
                continue;
            } else {
                if (path == null) {
                    throw new IllegalArgumentException("ACL entry before '# file:' header at line " + lineNo);
                }
                try {
                    entries.add(AclEntry.parse(line));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("Line " + lineNo + ": " + e.getMessage(), e);
                }
            }
        }
        if (path != null) {
            out.add(new ParsedAcl(path, owner, group, flags, Acl.of(entries)));
        }
        return out;
    }
}
