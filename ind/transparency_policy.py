"""Configuration objects for transparency-log verification."""

from dataclasses import dataclass


@dataclass(frozen=True)
class TransparencyVerifierPolicy:
    """Runtime policy knobs that shape current-root and consistency checks."""

    max_root_lag_seconds: int
    min_mirrors: int
    allow_unsafe_single_mirror: bool
    strict_mode: bool
    consistency_check_interval_seconds: int
    consistency_max_stale_seconds: int
    max_current_root_age_seconds: int
    current_root_future_skew_seconds: int

    @classmethod
    def from_values(
        cls,
        *,
        max_root_lag_seconds,
        min_mirrors,
        allow_unsafe_single_mirror,
        strict_mode,
        consistency_check_interval_seconds,
        consistency_max_stale_seconds,
        max_current_root_age_seconds,
        current_root_future_skew_seconds,
    ):
        return cls(
            max_root_lag_seconds=int(max_root_lag_seconds),
            min_mirrors=int(min_mirrors),
            allow_unsafe_single_mirror=bool(allow_unsafe_single_mirror),
            strict_mode=bool(strict_mode),
            consistency_check_interval_seconds=int(consistency_check_interval_seconds),
            consistency_max_stale_seconds=int(consistency_max_stale_seconds),
            max_current_root_age_seconds=int(max_current_root_age_seconds),
            current_root_future_skew_seconds=int(current_root_future_skew_seconds),
        )
