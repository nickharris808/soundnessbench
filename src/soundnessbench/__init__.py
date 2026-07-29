"""soundnessbench -- a public benchmark for guard-soundness tools.

Every task's answer is computed by exhaustive point-by-point enumeration, so the
ground truth shares no code with anything being graded.

The headline metric is not accuracy. It is the soundness gate: a tool that ever
says SOUND about an unsound guard fails, regardless of every other number.
"""

from .baselines import BASELINES, run_baseline
from .scoring import ABSTAIN, SOUND, UNSOUND, Answer, Score, score_submission
from .tasks import FAMILIES, Task, brute_force_over_acceptance, generate_suite

__version__ = "0.3.1"

__all__ = [
    "generate_suite",
    "Task",
    "FAMILIES",
    "brute_force_over_acceptance",
    "score_submission",
    "Score",
    "Answer",
    "SOUND",
    "UNSOUND",
    "ABSTAIN",
    "run_baseline",
    "BASELINES",
    "__version__",
]
