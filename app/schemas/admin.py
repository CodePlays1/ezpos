from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AdminSetupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    setup_token: str = Field(min_length=32, max_length=128)
    username: str = Field(
        min_length=3,
        max_length=60,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,59}$",
    )
    password: str = Field(min_length=12, max_length=128)
    signing_key_password: str = Field(min_length=1, max_length=256)


class AdminUnlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signing_key_password: str = Field(min_length=1, max_length=256)
