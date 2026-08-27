"""Trust layer: machinery that makes the confidence score *trustworthy* rather
than merely sophisticated — source-independence tracking (Phase 5a) and, later,
calibration and analytics.
"""

from .independence import (
    class_of,
    class_of_observation,
    corroboration,
    independence_breadth,
    independent_classes,
)

__all__ = [
    "class_of",
    "class_of_observation",
    "independent_classes",
    "independence_breadth",
    "corroboration",
]
