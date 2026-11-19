package io.github.whatheheckisthis.fsgov.config;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Repository conventions enforced in the build: no TypeScript, JavaScript or
 * shell sources; documentation uses console fences rather than shell fences;
 * prose avoids em and en dashes; nothing looks like a committed secret.
 */
class RepositoryPolicyTest {

    private static final Set<String> FORBIDDEN_SUFFIXES = Set.of(
            ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".sh", ".bash", ".zsh", ".ksh");

    @Test
    void noScriptSourcesInRepository() {
        List<String> found = new ArrayList<>();
        for (Path p : RepoFiles.all()) {
            String name = p.getFileName().toString().toLowerCase();
            for (String s : FORBIDDEN_SUFFIXES) {
                if (name.endsWith(s)) {
                    found.add(RepoFiles.root().relativize(p).toString());
                }
            }
        }
        assertTrue(found.isEmpty(), "forbidden file types: " + found);
    }

    @Test
    void markdownUsesConsoleFencesAndNoDashes() throws Exception {
        List<String> problems = new ArrayList<>();
        for (Path p : RepoFiles.all()) {
            if (!p.getFileName().toString().endsWith(".md")) {
                continue;
            }
            List<String> lines = Files.readAllLines(p);
            for (int i = 0; i < lines.size(); i++) {
                String l = lines.get(i).strip();
                if (l.matches("^```\\s*(bash|sh|shell|zsh|ksh)\\b.*")) {
                    problems.add(RepoFiles.root().relativize(p) + ":" + (i + 1) + " shell fence");
                }
                if (l.indexOf('\u2014') >= 0 || l.indexOf('\u2013') >= 0) {
                    problems.add(RepoFiles.root().relativize(p) + ":" + (i + 1) + " em or en dash");
                }
            }
        }
        assertTrue(problems.isEmpty(), String.join("\n", problems));
    }

    @Test
    void noObviousSecretsCommitted() throws Exception {
        List<String> problems = new ArrayList<>();
        for (Path p : RepoFiles.all()) {
            String name = p.getFileName().toString();
            // Binary files are not read as text; PNG figures live in docs/screenshots/.
            if (name.endsWith(".jar") || name.endsWith(".class") || name.endsWith(".png")) {
                continue;
            }
            if (name.equals("local.properties") || name.endsWith(".cs") || name.endsWith(".keystore") || name.endsWith(".jks")) {
                problems.add(RepoFiles.root().relativize(p) + " must not be committed");
                continue;
            }
            String text = Files.readString(p);
            if (text.contains("-----BEGIN") && text.contains("PRIVATE" + " KEY-----")) {
                problems.add(RepoFiles.root().relativize(p) + " contains a private key");
            }
        }
        assertTrue(problems.isEmpty(), String.join("\n", problems));
    }
}
