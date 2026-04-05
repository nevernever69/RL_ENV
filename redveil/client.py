"""RedVeil Environment Client."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import RedVeilAction, RedVeilObservation


class RedVeilEnv(EnvClient[RedVeilAction, RedVeilObservation, State]):
    """Client for the RedVeil Environment.

    Example:
        >>> with RedVeilEnv(base_url="http://localhost:8000").sync() as client:
        ...     result = client.reset(task_id="easy_recon")
        ...     result = client.step(RedVeilAction(action_type="scan", target="80"))
    """

    def _step_payload(self, action: RedVeilAction) -> Dict:
        payload = {
            "action_type": action.action_type.value,
            "target": action.target,
        }
        if action.payload is not None:
            payload["payload"] = action.payload
        return payload

    def _parse_result(self, payload: Dict) -> StepResult[RedVeilObservation]:
        obs_data = payload.get("observation", {})
        observation = RedVeilObservation(
            observation_text=obs_data.get("observation_text", ""),
            budget_remaining=obs_data.get("budget_remaining", 0),
            task_id=obs_data.get("task_id", ""),
            task_description=obs_data.get("task_description", ""),
            milestones_reached=obs_data.get("milestones_reached", []),
            done=payload.get("done", False),
            reward=payload.get("reward"),
            metadata=obs_data.get("metadata", {}),
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
