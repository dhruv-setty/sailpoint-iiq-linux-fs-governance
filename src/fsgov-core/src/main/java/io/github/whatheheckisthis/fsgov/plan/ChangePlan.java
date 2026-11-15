package io.github.whatheheckisthis.fsgov.plan;

import java.util.List;

/**
 * An ordered list of change steps with the warnings raised while planning
 * and the requests that needed no change because the target already matched.
 */
public record ChangePlan(List<ChangeStep> steps, List<PlanWarning> warnings, List<String> alreadySatisfied) {

    public ChangePlan {
        steps = List.copyOf(steps);
        warnings = List.copyOf(warnings);
        alreadySatisfied = List.copyOf(alreadySatisfied);
    }

    /** True when executing the plan would change nothing on the target. */
    public boolean isNoOp() {
        return steps.isEmpty();
    }

    public boolean hasWarning(PlanWarning.Code code) {
        return warnings.stream().anyMatch(w -> w.code() == code);
    }

    /** The steps in display form, one per line, for provisioning results and evidence. */
    public List<String> describe() {
        return steps.stream().map(ChangeStep::equivalentCommand).toList();
    }
}
