package io.github.whatheheckisthis.fsgov.iiq;

import io.github.whatheheckisthis.fsgov.model.Account;
import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.FilesystemType;
import io.github.whatheheckisthis.fsgov.model.Group;
import io.github.whatheheckisthis.fsgov.model.PathEntry;
import io.github.whatheheckisthis.fsgov.model.PosixMode;
import io.github.whatheheckisthis.fsgov.model.AclEntry;
import io.github.whatheheckisthis.fsgov.model.AclTag;
import io.github.whatheheckisthis.fsgov.parse.ExportsParser;
import io.github.whatheheckisthis.fsgov.parse.GetfaclParser;
import io.github.whatheheckisthis.fsgov.parse.ParsedAcl;
import sailpoint.object.ResourceObject;
import sailpoint.object.Schema;
import sailpoint.tools.CloseableIterator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Reads the collector inventory: passwd and group in getent format,
 * acl.txt from getfacl, exports from /etc/exports, and paths.tsv with
 * path, uid, gid, mode, filesystem type and acl mount flag for each
 * governed path.
 */
final class InventoryReader {

    private final Path dir;

    InventoryReader(Path dir) {
        this.dir = dir;
    }

    FilesystemSnapshot snapshot() throws IOException {
        FilesystemSnapshot.Builder b = FilesystemSnapshot.builder();
        for (String line : lines("passwd")) {
            String[] f = line.split(":", -1);
            b.account(new Account(f[0], Integer.parseInt(f[2]), Integer.parseInt(f[3])));
        }
        for (String line : lines("group")) {
            String[] f = line.split(":", -1);
            Set<String> members = f.length > 3 && !f[3].isEmpty() ? new TreeSet<>(Arrays.asList(f[3].split(","))) : Set.of();
            b.group(new Group(f[0], Integer.parseInt(f[2]), members, Set.of()));
        }
        List<ParsedAcl> acls = new GetfaclParser().parse(read("acl.txt"));
        for (String line : lines("paths.tsv")) {
            String[] f = line.split("\t", -1);
            ParsedAcl acl = acls.stream().filter(a -> a.path().equals(f[0])).findFirst().orElse(null);
            b.path(new PathEntry(f[0], Integer.parseInt(f[1]), Integer.parseInt(f[2]), PosixMode.parse(f[3]),
                    acl == null ? null : acl.acl(), FilesystemType.valueOf(f[4]), true, Boolean.parseBoolean(f[5])));
        }
        new ExportsParser().parse(read("exports")).forEach(b::export);
        return b.build();
    }

    CloseableIterator<ResourceObject> iterate(String objectType, Schema schema) throws IOException {
        List<ResourceObject> objects = build(objectType);
        Iterator<ResourceObject> it = objects.iterator();
        return new CloseableIterator<>() {
            public boolean hasNext() {
                return it.hasNext();
            }

            public ResourceObject next() {
                return it.next();
            }

            public void close() {
            }
        };
    }

    ResourceObject find(String objectType, Schema schema, String identity) throws IOException {
        return build(objectType).stream().filter(o -> identity.equals(o.getIdentity())).findFirst().orElse(null);
    }

    private List<ResourceObject> build(String objectType) throws IOException {
        FilesystemSnapshot s = snapshot();
        List<ResourceObject> out = new ArrayList<>();
        if ("group".equals(objectType)) {
            for (Group g : s.groups().values()) {
                ResourceObject ro = new ResourceObject(g.name(), "group");
                ro.put("name", g.name());
                ro.put("gid", g.gid());
                ro.put("nestedGroups", new ArrayList<>(g.nestedGroups()));
                out.add(ro);
            }
            return out;
        }
        for (Account a : s.accounts().values()) {
            ResourceObject ro = new ResourceObject(a.name(), "account");
            ro.put("name", a.name());
            ro.put("uid", a.uid());
            ro.put("primaryGid", a.primaryGid());
            ro.put("groups", new ArrayList<>(s.directGroupsOf(a.name())));
            List<String> direct = new ArrayList<>();
            for (PathEntry p : s.paths().values()) {
                for (AclEntry e : p.acl().accessEntries()) {
                    if (e.tag() == AclTag.USER && e.qualifier().equals(a.name())) {
                        direct.add(p.path() + ":" + e.permissions());
                    }
                }
            }
            ro.put("directPermissions", direct);
            out.add(ro);
        }
        return out;
    }

    private List<String> lines(String name) throws IOException {
        Path p = dir.resolve(name);
        if (!Files.exists(p)) {
            return List.of();
        }
        return Files.readAllLines(p, StandardCharsets.UTF_8).stream()
                .filter(l -> !l.isBlank() && !l.startsWith("#")).toList();
    }

    private String read(String name) throws IOException {
        Path p = dir.resolve(name);
        return Files.exists(p) ? Files.readString(p, StandardCharsets.UTF_8) : "";
    }
}
