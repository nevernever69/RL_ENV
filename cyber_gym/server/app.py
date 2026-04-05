"""FastAPI application for the CyberGym Environment."""

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:
    raise ImportError(
        "openenv is required. Install with: pip install openenv-core[core]"
    ) from e

try:
    from ..models import CyberGymAction, CyberGymObservation
    from .cyber_gym_environment import CyberGymEnvironment
except (ModuleNotFoundError, ImportError):
    from models import CyberGymAction, CyberGymObservation
    from server.cyber_gym_environment import CyberGymEnvironment


# Singleton: OpenEnv calls the factory on every request, so we return
# the same instance to preserve state across reset() -> step() calls.
_singleton_env = CyberGymEnvironment()


def _env_factory() -> CyberGymEnvironment:
    return _singleton_env


app = create_app(
    _env_factory,
    CyberGymAction,
    CyberGymObservation,
    env_name="cyber_gym",
    max_concurrent_envs=4,
)


def main(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    main(port=args.port)
