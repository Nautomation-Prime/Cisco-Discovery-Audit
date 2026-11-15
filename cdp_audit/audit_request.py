"""Validated operator input for one audit run.

The setup screen hands its raw form values to AuditRequest; anything wrong is
reported back to the operator before a single SSH session is opened. Keeping
this out of the Textual screen also makes it unit-testable.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

from .discovery import IPFilter
from .net_types import HostOrIP, OptionalHostOrIP

MAX_SITE_NAME = 50
MAX_SEEDS = 500

_FIELD_LABELS = {
    "site_name": "Site name",
    "seeds": "Seed devices",
    "primary_user": "Primary username",
    "primary_pass": "Primary password",
    "answer_user": "Fallback username",
    "answer_pass": "Fallback password",
    "jump_host": "Jump host",
    "ip_filter": "IP filter",
}


class AuditRequest(BaseModel):
    """Everything the discovery run needs from the operator.

    Passwords are SecretStr so they render as '**********' in reprs, logs and
    Textual's crash traceback (which prints local variables). Call
    get_secret_value() only at the point of handing them to SSH.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    site_name: str
    seeds: List[HostOrIP] = Field(min_length=1, max_length=MAX_SEEDS)
    primary_user: str
    primary_pass: SecretStr
    answer_user: Optional[str] = None
    answer_pass: Optional[SecretStr] = None
    jump_host: OptionalHostOrIP = ""
    ip_filter: IPFilter = Field(default_factory=IPFilter)

    @field_validator("site_name", mode="before")
    @classmethod
    def _site_name(cls, value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("is required")
        if len(text) > MAX_SITE_NAME:
            raise ValueError(f"must be {MAX_SITE_NAME} characters or fewer")
        return text

    @field_validator("seeds", mode="before")
    @classmethod
    def _split_seeds(cls, value: Any) -> Any:
        # Commas are documented; semicolons and whitespace are accepted too,
        # because seed lists are often pasted from Excel or a ticket.
        if isinstance(value, str):
            return [part for part in re.split(r"[,;\s]+", value) if part]
        return value

    @field_validator("primary_user", mode="before")
    @classmethod
    def _primary_user(cls, value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("is required")
        return text

    @field_validator("primary_pass", mode="before")
    @classmethod
    def _primary_pass(cls, value: Any) -> Any:
        # Passwords are deliberately not stripped: spaces may be significant.
        if not value:
            raise ValueError("is required")
        return value

    @field_validator("answer_user", mode="before")
    @classmethod
    def _blank_user_is_none(cls, value: Any) -> Optional[str]:
        text = str(value or "").strip()
        return text or None

    @field_validator("answer_pass", mode="before")
    @classmethod
    def _blank_pass_is_none(cls, value: Any) -> Any:
        return value or None

    @field_validator("ip_filter", mode="before")
    @classmethod
    def _parse_ip_filter(cls, value: Any) -> IPFilter:
        if isinstance(value, IPFilter):
            return value
        return IPFilter(str(value or ""))

    @model_validator(mode="after")
    def _fallback_pair(self) -> "AuditRequest":
        if (self.answer_user is None) != (self.answer_pass is None):
            raise ValueError(
                "Provide both a fallback username and password, or leave both blank."
            )
        return self

    @property
    def has_fallback(self) -> bool:
        return self.answer_user is not None and self.answer_pass is not None


def describe_validation_error(exc: ValidationError) -> str:
    """Turn a ValidationError into one operator-readable line per problem."""
    messages: List[str] = []
    for error in exc.errors():
        message = error["msg"].removeprefix("Value error, ")
        loc = error["loc"]
        if not loc:
            messages.append(message)
            continue
        label = _FIELD_LABELS.get(str(loc[0]), str(loc[0]))
        if error["type"] == "too_short" and loc[0] == "seeds":
            message = "at least one seed device is required"
        elif error["type"] == "too_long" and loc[0] == "seeds":
            message = f"too many seeds provided (max {MAX_SEEDS})"
        messages.append(f"{label}: {message}")
    return "\n".join(messages)
