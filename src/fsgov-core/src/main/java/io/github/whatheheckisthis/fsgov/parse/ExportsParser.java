package io.github.whatheheckisthis.fsgov.parse;

import io.github.whatheheckisthis.fsgov.model.NfsClientRule;
import io.github.whatheheckisthis.fsgov.model.NfsExport;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Parses {@code /etc/exports} as exports(5) defines it: comments, backslash
 * continuation, quoted paths, a leading {@code -opts} default list that
 * applies to every client on the line, and clients written with or without
 * an option list. A client without options receives the defaults only.
 */
public final class ExportsParser {

    public List<NfsExport> parse(String text) {
        List<NfsExport> out = new ArrayList<>();
        String joined = text.replaceAll("\\\\\\R", " ");
        for (String raw : joined.split("\\R")) {
            int hash = raw.indexOf('#');
            String line = (hash >= 0 ? raw.substring(0, hash) : raw).strip();
            if (line.isEmpty()) {
                continue;
            }
            out.add(parseLine(line));
        }
        return out;
    }

    private NfsExport parseLine(String line) {
        String path;
        String rest;
        if (line.startsWith("\"")) {
            int end = line.indexOf('"', 1);
            if (end < 0) {
                throw new IllegalArgumentException("Unterminated quoted path: " + line);
            }
            path = line.substring(1, end);
            rest = line.substring(end + 1).strip();
        } else {
            String[] parts = line.split("\\s+", 2);
            path = parts[0];
            rest = parts.length > 1 ? parts[1] : "";
        }
        List<String> defaults = new ArrayList<>();
        List<NfsClientRule> clients = new ArrayList<>();
        for (String token : rest.isEmpty() ? new String[0] : rest.split("\\s+")) {
            if (token.startsWith("-")) {
                defaults.addAll(Arrays.asList(token.substring(1).split(",")));
                continue;
            }
            int open = token.indexOf('(');
            List<String> options = new ArrayList<>(defaults);
            String client = token;
            if (open >= 0) {
                if (!token.endsWith(")")) {
                    throw new IllegalArgumentException("Malformed client options: " + token);
                }
                client = token.substring(0, open);
                options.addAll(Arrays.asList(token.substring(open + 1, token.length() - 1).split(",")));
            }
            clients.add(new NfsClientRule(client.isEmpty() ? "*" : client, options));
        }
        return new NfsExport(path, clients);
    }
}
