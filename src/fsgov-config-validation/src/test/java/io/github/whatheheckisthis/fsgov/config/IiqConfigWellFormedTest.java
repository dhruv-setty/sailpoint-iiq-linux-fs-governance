package io.github.whatheheckisthis.fsgov.config;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentType;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every IdentityIQ artifact under config/ must be well formed, declare the
 * sailpoint.dtd DOCTYPE with a name matching its root element, and use one of
 * the object classes this project ships.
 */
class IiqConfigWellFormedTest {

    private static final Set<String> ROOTS = Set.of(
            "sailpoint", "Application", "Rule", "Workflow", "TaskDefinition", "TaskSchedule",
            "CertificationDefinition", "Policy", "Bundle", "ManagedAttribute", "Configuration");

    @Test
    void configDirectoryIsNotEmpty() {
        assertTrue(RepoFiles.under("config", ".xml").size() >= 15, "expected the full config set");
    }

    @TestFactory
    Stream<DynamicTest> everyConfigFileIsWellFormedWithSailpointDoctype() {
        return RepoFiles.under("config", ".xml").stream().map(p -> DynamicTest.dynamicTest(
                RepoFiles.root().relativize(p).toString(), () -> check(p)));
    }

    private static void check(Path p) throws Exception {
        String head = Files.readString(p);
        assertTrue(head.startsWith("<?xml"), "XML declaration must come first");
        Document d = XmlSupport.parse(p);
        DocumentType dt = d.getDoctype();
        assertNotNull(dt, "DOCTYPE sailpoint.dtd is required");
        assertEquals("sailpoint.dtd", dt.getSystemId(), "system id");
        assertEquals("sailpoint.dtd", dt.getPublicId(), "public id");
        String root = d.getDocumentElement().getTagName();
        assertEquals(root, dt.getName(), "DOCTYPE name must match the root element");
        assertTrue(ROOTS.contains(root), "unexpected root element " + root);
        if ("Rule".equals(root)) {
            checkRule(d.getDocumentElement());
        }
        NodeList rules = d.getElementsByTagName("Rule");
        for (int i = 0; i < rules.getLength(); i++) {
            checkRule((Element) rules.item(i));
        }
    }

    private static void checkRule(Element rule) {
        assertEquals("beanshell", rule.getAttribute("language"), "rules are BeanShell");
        assertFalse(rule.getAttribute("name").isBlank(), "rule name");
        NodeList src = rule.getElementsByTagName("Source");
        assertEquals(1, src.getLength(), "one Source per rule");
        assertFalse(src.item(0).getTextContent().isBlank(), "rule source must not be empty");
    }

    @TestFactory
    Stream<DynamicTest> deployXmlIsWellFormed() {
        List<Path> files = RepoFiles.under("deploy", ".xml");
        assertFalse(files.isEmpty());
        return files.stream().map(p -> DynamicTest.dynamicTest(
                RepoFiles.root().relativize(p).toString(), () -> XmlSupport.parse(p)));
    }

    @TestFactory
    Stream<DynamicTest> mavenPomsAreWellFormed() {
        return RepoFiles.all().stream()
                .filter(p -> p.getFileName().toString().equals("pom.xml"))
                .map(p -> DynamicTest.dynamicTest(RepoFiles.root().relativize(p).toString(), () -> XmlSupport.parse(p)));
    }
}
