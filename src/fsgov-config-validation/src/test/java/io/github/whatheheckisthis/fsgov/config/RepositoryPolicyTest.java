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
 * A {@code .cs} file is an Elytron credential store everywhere except under
 * the .NET module, where it must be C# source text.
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
            if (name.endsWith(".jar") || name.endsWith(".class")) {
                continue;
            }
            String rel = RepoFiles.root().relativize(p).toString().replace('\\', '/');
            if (name.endsWith(".cs") && rel.startsWith(RepoFiles.DOTNET_MODULE)) {
                if (!isCSharpSource(p)) {
                    problems.add(rel + " has a .cs name but is not C# source text");
                }
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

    /** UTF-8 text with no NUL bytes that declares a namespace or a using directive. */
    private static boolean isCSharpSource(Path p) throws Exception {
        byte[] bytes = Files.readAllBytes(p);
        for (byte b : bytes) {
            if (b == 0) {
                return false;
            }
        }
        String text;
        try {
            text = java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                    .decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        } catch (java.nio.charset.CharacterCodingException e) {
            return false;
        }
        return text.contains("namespace ") || text.contains("using ");
    }
}
