"""Data models for the RedVeil Environment."""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import Field

from openenv.core.env_server.types import Action, Observation


class ActionType(str, Enum):
    SCAN = "scan"
    FUZZ = "fuzz"
    INJECT_PAYLOAD = "inject_payload"
    LOGIN = "login"
    ANALYZE = "analyze"
    FETCH_CONFIG = "fetch_config"


class RedVeilAction(Action):
    """Action for the RedVeil environment.

    The agent chooses a tool and a target to act on.
    """

    action_type: ActionType = Field(..., description="The tool to use: scan, fuzz, inject_payload, login, analyze, or fetch_config")
    target: str = Field(..., description="The target to act on (e.g. port number, endpoint path, or credentials)")
    payload: Optional[str] = Field(default=None, description="Optional payload for inject/analyze actions (e.g. auth token)")


class EndpointInfo(Dict):
    pass


class RedVeilObservation(Observation):
    """Observation from the RedVeil environment."""

    observation_text: str = Field(default="", description="Human-readable observation text (LLM-compatible)")
    budget_remaining: int = Field(default=0, description="Number of actions the agent can still take")
    task_id: str = Field(default="", description="Current task identifier")
    task_description: str = Field(default="", description="Description of the current task objective")
    milestones_reached: List[str] = Field(default_factory=list, description="List of milestones the agent has achieved so far")
