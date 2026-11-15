package io.github.whatheheckisthis.fsgov.config;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

/** Locates repository files for the validation tests. */
final class RepoFiles {

    private RepoFiles() {
    }

    static Path root() {
        String prop = System.getProperty("fsgov.repo.root");
        Path p = prop != null ? Path.of(prop) : Path.of("../..");
        return p.toAbsolutePath().normalize();
    }

    static List<Path> under(String dir, String suffix) {
        Path base = root().resolve(dir);
        if (!Files.isDirectory(base)) {
            return List.of();
        }
        try (Stream<Path> s = Files.walk(base)) {
            return s.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(suffix))
                    .sorted()
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Every tracked-looking file, excluding build output and VCS metadata. */
    static List<Path> all() {
        try (Stream<Path> s = Files.walk(root())) {
            return s.filter(Files::isRegularFile)
                    .filter(p -> {
                        String rel = root().relativize(p).toString().replace('\\', '/');
                        return !rel.startsWith(".git/") && !rel.contains("/target/") && !rel.startsWith("target/");
                    })
                    .sorted()
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
