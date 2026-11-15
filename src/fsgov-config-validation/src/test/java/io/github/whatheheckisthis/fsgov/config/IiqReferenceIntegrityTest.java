package io.github.whatheheckisthis.fsgov.config;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross checks between artifacts: every Reference to a Rule, Application,
 * Bundle or CertificationDefinition resolves to an object defined in this
 * project or to a known IdentityIQ default, every rule named in an
 * attribute map exists, and every %%TOKEN%% has a value in
 * sandbox.target.properties.
 */
class IiqReferenceIntegrityTest {

    /** Objects that ship with IdentityIQ and are referenced, not defined, here. */
    private static final Set<String> PLATFORM_OBJECTS = Set.of(
            "TaskDefinition:Account Aggregation",
            "TaskDefinition:Account Group Aggregation",
            "TaskDefinition:Refresh Identity Cube");

    private static final Set<String> RULE_NAME_KEYS = Set.of(
            "buildMapRule", "beforeProvisioningRule", "afterProvisioningRule",
            "exclusionRuleName", "phaseChangeRuleName");

    private static final Map<String, Set<String>> defined = new HashMap<>();
    private static final List<String[]> references = new ArrayList<>();
    private static final List<String[]> ruleKeys = new ArrayList<>();
    private static final Set<String> tokens = new TreeSet<>();

    @BeforeAll
    static void index() throws Exception {
        Pattern token = Pattern.compile("%%[A-Z0-9_]+%%");
        for (Path p : RepoFiles.under("config", ".xml")) {
            Document d = XmlSupport.parse(p);
            String rel = RepoFiles.root().relativize(p).toString();
            for (String cls : List.of("Application", "Rule", "Bundle", "CertificationDefinition", "Workflow", "Policy", "TaskDefinition")) {
                NodeList n = d.getElementsByTagName(cls);
                for (int i = 0; i < n.getLength(); i++) {
                    Element e = (Element) n.item(i);
                    if (!e.getAttribute("name").isEmpty()) {
                        defined.computeIfAbsent(cls, k -> new HashSet<>()).add(e.getAttribute("name"));
                    }
                }
            }
            NodeList refs = d.getElementsByTagName("Reference");
            for (int i = 0; i < refs.getLength(); i++) {
                Element r = (Element) refs.item(i);
                String cls = r.getAttribute("class").replace("sailpoint.object.", "");
                references.add(new String[] {rel, cls, r.getAttribute("name")});
            }
            NodeList entries = d.getElementsByTagName("entry");
            for (int i = 0; i < entries.getLength(); i++) {
                Element e = (Element) entries.item(i);
                if (RULE_NAME_KEYS.contains(e.getAttribute("key"))) {
                    ruleKeys.add(new String[] {rel, e.getAttribute("key"), e.getAttribute("value")});
                }
            }
            Matcher m = token.matcher(Files.readString(p));
            while (m.find()) {
                tokens.add(m.group());
            }
        }
    }

    @Test
    void everyObjectReferenceResolves() {
        List<String> missing = new ArrayList<>();
        for (String[] r : references) {
            String cls = r[1];
            String name = r[2];
            if ("Identity".equals(cls) || name.startsWith("%%")) {
                continue;
            }
            boolean ok = defined.getOrDefault(cls, Set.of()).contains(name) || PLATFORM_OBJECTS.contains(cls + ":" + name);
            if (!ok) {
                missing.add(r[0] + " -> " + cls + ":" + name);
            }
        }
        assertTrue(missing.isEmpty(), "unresolved references: " + missing);
    }

    @Test
    void everyRuleNamedInAttributesExists() {
        List<String> missing = new ArrayList<>();
        for (String[] k : ruleKeys) {
            if (!defined.getOrDefault("Rule", Set.of()).contains(k[2])) {
                missing.add(k[0] + " " + k[1] + "=" + k[2]);
            }
        }
        assertTrue(missing.isEmpty(), "rules named in attributes but not defined: " + missing);
    }

    @Test
    void policiesNamedInRefreshExist() {
        assertTrue(defined.getOrDefault("Policy", Set.of()).contains("FSGov SoD Finance Write vs Audit Write"));
    }

    @Test
    void everyTokenHasATargetValue() throws Exception {
        Properties props = new Properties();
        try (var in = Files.newBufferedReader(RepoFiles.root().resolve("sandbox.target.properties"))) {
            props.load(in);
        }
        Set<String> missing = new TreeSet<>(tokens);
        missing.removeAll(props.stringPropertyNames());
        assertTrue(missing.isEmpty(), "tokens without a value in sandbox.target.properties: " + missing);
        assertTrue(tokens.size() >= 10, "expected token usage across config");
    }
}
