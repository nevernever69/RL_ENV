"""Wrapper to re-export the app from redveil.server.app for openenv compatibility."""
from redveil.server.app import app  # noqa: F401


def main(host: str = "0.0.0.0", port: int = 7860):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
