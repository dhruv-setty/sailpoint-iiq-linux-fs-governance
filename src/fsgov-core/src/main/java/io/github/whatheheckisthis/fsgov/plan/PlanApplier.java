package io.github.whatheheckisthis.fsgov.plan;

import io.github.whatheheckisthis.fsgov.model.FilesystemSnapshot;
import io.github.whatheheckisthis.fsgov.model.Group;
import io.github.whatheheckisthis.fsgov.model.PathEntry;

import java.util.Optional;

/**
 * Applies a plan to a snapshot in memory. Used to predict the end state for
 * approval and certification evidence, and in tests to prove idempotency.
 * Each step is applied with the same semantics the host executor must honour.
 */
public final class PlanApplier {

    public FilesystemSnapshot apply(FilesystemSnapshot snapshot, ChangePlan plan) {
        FilesystemSnapshot current = snapshot;
        for (ChangeStep step : plan.steps()) {
            current = apply(current, step);
        }
        return current;
    }

    public FilesystemSnapshot apply(FilesystemSnapshot s, ChangeStep step) {
        FilesystemSnapshot.Builder b = s.toBuilder();
        if (step instanceof ChangeStep.CreateGroup c) {
            Optional<Group> existing = s.group(c.group());
            if (existing.isPresent()) {
                if (existing.get().gid() != c.gid()) {
                    throw new IllegalStateException(c.group() + " exists with gid " + existing.get().gid());
                }
                return s;
            }
            s.groupByGid(c.gid()).ifPresent(g -> {
                throw new IllegalStateException("gid " + c.gid() + " already used by " + g.name());
            });
            b.group(Group.of(c.group(), c.gid()));
        } else if (step instanceof ChangeStep.AddMembership a) {
            require(s.account(a.account()).isPresent(), "account " + a.account() + " not found");
            Group g = s.group(a.group()).orElseThrow(() -> new IllegalStateException("group " + a.group() + " not found"));
            b.group(g.withMember(a.account()));
        } else if (step instanceof ChangeStep.RemoveMembership r) {
            s.group(r.group()).ifPresent(g -> b.group(g.withoutMember(r.account())));
        } else {
            String pathName = AclOps.pathOf(step);
            PathEntry p = s.path(pathName).orElseThrow(() -> new IllegalStateException("path " + pathName + " not found"));
            b.path(p.withAcl(AclOps.apply(p.acl(), step)));
        }
        return b.build();
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
