package io.github.whatheheckisthis.fsgov.plan;

import io.github.whatheheckisthis.fsgov.model.AclEntry;
import io.github.whatheheckisthis.fsgov.model.AclTag;
import io.github.whatheheckisthis.fsgov.model.PermissionSet;

import java.util.ArrayList;
import java.util.List;

/**
 * Line oriented, tab separated encoding of change steps for the change queue
 * between IdentityIQ and the host executor. The executor parses fields; it
 * never interprets text as a command. Values containing a tab, carriage
 * return or newline are rejected at encode time, so a crafted group or path
 * name cannot inject a second step.
 */
public final class ChangePlanCodec {

    public static final String HEADER = "#fsgov-plan\tv1";

    public String encode(List<ChangeStep> steps) {
        StringBuilder sb = new StringBuilder(HEADER).append('\n');
        for (ChangeStep s : steps) {
            sb.append(String.join("\t", fields(s))).append('\n');
        }
        return sb.toString();
    }

    private static List<String> fields(ChangeStep s) {
        List<String> f = new ArrayList<>();
        if (s instanceof ChangeStep.CreateGroup c) {
            f.addAll(List.of("CREATE_GROUP", c.group(), Integer.toString(c.gid())));
        } else if (s instanceof ChangeStep.AddMembership a) {
            f.addAll(List.of("ADD_MEMBER", a.account(), a.group()));
        } else if (s instanceof ChangeStep.RemoveMembership r) {
            f.addAll(List.of("REMOVE_MEMBER", r.account(), r.group()));
        } else if (s instanceof ChangeStep.SetAclEntry e) {
            f.addAll(List.of("SET_ACL", e.path(), e.entry().toText()));
        } else if (s instanceof ChangeStep.RemoveAclEntry x) {
            f.addAll(List.of("REMOVE_ACL", x.path(), x.tag().name(), x.qualifier(), Boolean.toString(x.defaultScope())));
        } else {
            ChangeStep.SetMask m = (ChangeStep.SetMask) s;
            f.addAll(List.of("SET_MASK", m.path(), Boolean.toString(m.defaultScope()), m.mask().toString()));
        }
        for (String v : f) {
            if (v.indexOf('\t') >= 0 || v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0) {
                throw new IllegalArgumentException("Field contains a control character: " + v.replaceAll("[\\t\\r\\n]", "?"));
            }
        }
        return f;
    }

    public List<ChangeStep> decode(String text) {
        String[] lines = text.split("\n", -1);
        if (lines.length == 0 || !HEADER.equals(lines[0])) {
            throw new IllegalArgumentException("Missing or unknown plan header");
        }
        List<ChangeStep> out = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].isEmpty()) {
                continue;
            }
            String[] f = lines[i].split("\t", -1);
            out.add(decodeLine(f, i + 1));
        }
        return out;
    }

    private static ChangeStep decodeLine(String[] f, int lineNo) {
        try {
            switch (f[0]) {
                case "CREATE_GROUP":
                    expect(f, 3);
                    return new ChangeStep.CreateGroup(f[1], Integer.parseInt(f[2]));
                case "ADD_MEMBER":
                    expect(f, 3);
                    return new ChangeStep.AddMembership(f[1], f[2]);
                case "REMOVE_MEMBER":
                    expect(f, 3);
                    return new ChangeStep.RemoveMembership(f[1], f[2]);
                case "SET_ACL":
                    expect(f, 3);
                    return new ChangeStep.SetAclEntry(f[1], AclEntry.parse(f[2]));
                case "REMOVE_ACL":
                    expect(f, 5);
                    return new ChangeStep.RemoveAclEntry(f[1], AclTag.valueOf(f[2]), f[3], Boolean.parseBoolean(f[4]));
                case "SET_MASK":
                    expect(f, 4);
                    return new ChangeStep.SetMask(f[1], Boolean.parseBoolean(f[2]), PermissionSet.parse(f[3]));
                default:
                    throw new IllegalArgumentException("unknown step " + f[0]);
            }
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Line " + lineNo + ": " + e.getMessage(), e);
        }
    }

    private static void expect(String[] f, int n) {
        if (f.length != n) {
            throw new IllegalArgumentException("expected " + n + " fields, found " + f.length);
        }
    }
}
