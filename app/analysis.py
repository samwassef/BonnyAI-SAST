"""URL-analysis request contract."""

# Imports used by the request models, services, and helpers below.
from pydantic import BaseModel, ConfigDict, Field, field_validator


# Define the URL and question accepted by the webpage-analysis endpoint.
class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=8192)
    question: str = Field(min_length=1, max_length=4000)

    # Reject questions containing only whitespace, which length validation would allow.
    @field_validator("question")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Question is required")
        return value
