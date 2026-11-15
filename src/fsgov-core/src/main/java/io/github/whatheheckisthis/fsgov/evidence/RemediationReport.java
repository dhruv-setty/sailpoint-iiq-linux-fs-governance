package io.github.whatheheckisthis.fsgov.evidence;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

/**
 * Remediation evidence for one certification: every revoked item with its
 * verified outcome, tied to the digest of the change plan that carried out
 * the revocations.
 */
public final class RemediationReport {

    private final String certification;
    private final String planDigest;
    private final Instant capturedAt;
    private final List<RemediationRecord> records;

    /**
     * @param capturedAt when the after state was aggregated. Taken from the caller,
     *                   never from the clock, so the digest is reproducible.
     */
    public RemediationReport(String certification, String planDigest, Instant capturedAt,
                             List<RemediationRecord> records) {
        this.certification = certification;
        this.planDigest = planDigest;
        this.capturedAt = java.util.Objects.requireNonNull(capturedAt, "capturedAt");
        this.records = List.copyOf(records);
    }

    public String certification() {
        return certification;
    }

    public String planDigest() {
        return planDigest;
    }

    public Instant capturedAt() {
        return capturedAt;
    }

    public List<RemediationRecord> records() {
        return records;
    }

    public boolean allVerified() {
        return records.stream().allMatch(r -> r.outcome() == RemediationOutcome.VERIFIED);
    }

    public List<RemediationRecord> withOutcome(RemediationOutcome outcome) {
        return records.stream().filter(r -> r.outcome() == outcome).toList();
    }

    public String canonicalText() {
        StringBuilder sb = new StringBuilder("# ").append(certification).append('\t')
                .append(planDigest).append('\t').append(capturedAt).append('\n');
        for (RemediationRecord r : records) {
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
