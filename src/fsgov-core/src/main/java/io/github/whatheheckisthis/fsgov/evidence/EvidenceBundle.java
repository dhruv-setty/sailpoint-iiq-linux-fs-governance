package io.github.whatheheckisthis.fsgov.evidence;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

/**
 * An ordered, digestible set of evidence records for one certification
 * campaign or one remediation. The SHA-256 digest is computed over the
 * canonical lines with the campaign label, so an auditor can confirm that
 * evidence attached to a certification has not been edited since capture.
 */
public final class EvidenceBundle {

    private static final Comparator<EvidenceRecord> ORDER = Comparator
            .comparing(EvidenceRecord::path)
            .thenComparing(EvidenceRecord::account);

    private final String label;
    private final List<EvidenceRecord> records;

    public EvidenceBundle(String label, List<EvidenceRecord> records) {
        this.label = label;
        this.records = records.stream().sorted(ORDER).toList();
    }

    public String label() {
        return label;
    }

    public List<EvidenceRecord> records() {
        return records;
    }

    public List<EvidenceRecord> withStatus(EvidenceStatus status) {
        return records.stream().filter(r -> r.status() == status).toList();
    }

    /** Lines in canonical form, prefixed with the label line. */
    public String canonicalText() {
        StringBuilder sb = new StringBuilder("# ").append(label).append('\n');
        for (EvidenceRecord r : records) {
            sb.append(r.canonical()).append('\n');
        }
        return sb.toString();
    }

    public String sha256() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(canonicalText().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
