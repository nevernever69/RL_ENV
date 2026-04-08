"""RedVeil Environment Implementation.

A cybersecurity-themed RL environment where agents make decisions under
uncertainty, use tools effectively, and avoid deceptive signals.

This environment runs a REAL vulnerable Flask web application and sends
REAL HTTP requests. SQL injections are genuine, login bypasses are real,
and honeypot responses come from actual HTTP endpoints.

KEY DESIGN: Endpoints are HIDDEN. The agent only sees ports at the start.
Scanning a port reveals the endpoints hosted on it (mix of real + honeypots).
Endpoint paths are randomized per episode -- the agent cannot memorize routes.
"""

import threading
import time
from typing import Any, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

try:
    from ..models import ActionType, RedVeilAction, RedVeilObservation
    from ..noise import DeceptionEngine, NoiseEngine
    from ..tasks import ALL_TASKS, TaskConfig
    from ..grader import grade_task
    from ..vulnerable_app import create_vulnerable_app
except (ImportError, ModuleNotFoundError):
    from models import ActionType, RedVeilAction, RedVeilObservation
    from noise import DeceptionEngine, NoiseEngine
    from tasks import ALL_TASKS, TaskConfig
    from grader import grade_task
    from vulnerable_app import create_vulnerable_app


# ---------------------------------------------------------------------------
# Vulnerable app management
# ---------------------------------------------------------------------------

_vuln_app_started = False
_vuln_app_lock = threading.Lock()
VULN_APP_PORT = 5000
VULN_APP_URL = f"http://127.0.0.1:{VULN_APP_PORT}"


def _ensure_vuln_app_running():
    """Start the vulnerable Flask app in a background thread if not already running."""
    global _vuln_app_started

    with _vuln_app_lock:
        if _vuln_app_started:
            return

        app = create_vulnerable_app()

        def run_app():
            import logging
            log = logging.getLogger('werkzeug')
            log.setLevel(logging.WARNING)
            app.run(
                host='127.0.0.1',
                port=VULN_APP_PORT,
                debug=False,
                use_reloader=False,
                threaded=True,
            )

        thread = threading.Thread(target=run_app, daemon=True)
        thread.start()
        _vuln_app_started = True

        import requests
        for _ in range(30):
            try:
                resp = requests.get(f"{VULN_APP_URL}/health", timeout=1)
                if resp.status_code == 200:
                    return
            except requests.RequestException:
                pass
            time.sleep(0.1)


class RedVeilEnvironment(Environment):
    """RedVeil: Decision-making under uncertainty with real tool interaction.

    Endpoints are HIDDEN until the agent scans the port they live on.
    Paths are randomized per episode. Real HTTP requests are sent to a
    genuine vulnerable Flask application with real SQL injection vulnerabilities.
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self):
        super().__init__()
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._task: Optional[TaskConfig] = None
        self._noise_engine: Optional[NoiseEngine] = None
        self._deception_engine: Optional[DeceptionEngine] = None

        # Game state tracking
        self._budget_remaining: int = 0
        self._scan_counts: dict = {}
        self._revealed_endpoints: set = set()  # Endpoints revealed by scanning
        self._discovered_endpoints: set = set()  # Endpoints the agent has fuzzed
        self._fuzzed_endpoints: set = set()
        self._identified_real_ports: set = set()
        self._identified_fake_ports: set = set()
        self._vuln_found: bool = False
        self._vuln_endpoint: Optional[str] = None
        self._exploit_success: bool = False
        self._creds_extracted: bool = False
        self._extracted_creds: Optional[dict] = None
        self._admin_login: bool = False
        self._flagged_honeypots: set = set()
        self._action_log: list = []
        self._session_token: Optional[str] = None  # Token from /api/profile
        self._config_fetched: bool = False  # Found hidden paths via config
        self._hidden_endpoints_found: set = set()  # Endpoints found via config/robots
        self._low_priv_login: bool = False  # Logged in as non-admin user

        # Endpoint path -> EndpointConfig lookup
        self._endpoint_map: dict = {}

        _ensure_vuln_app_running()

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> RedVeilObservation:
        """Reset the environment with a specific task."""
        task_id = kwargs.get("task_id", "easy_recon")
        actual_seed = seed if seed is not None else 42

        self._task = ALL_TASKS.get(task_id, ALL_TASKS["easy_recon"])
        self._state = State(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
        )

        self._noise_engine = NoiseEngine(
            noise_level=self._task.noise_level,
            conflicting_scans=self._task.conflicting_scans,
            seed=actual_seed,
        )
        self._deception_engine = DeceptionEngine(
            deception_active=self._task.deception_active,
            target_base_url=VULN_APP_URL,
            seed=actual_seed,
        )

        # Reset game state
        self._budget_remaining = self._task.budget
        self._scan_counts = {}
        self._revealed_endpoints = set()
        self._discovered_endpoints = set()
        self._fuzzed_endpoints = set()
        self._identified_real_ports = set()
        self._identified_fake_ports = set()
        self._vuln_found = False
        self._vuln_endpoint = None
        self._exploit_success = False
        self._creds_extracted = False
        self._extracted_creds = None
        self._admin_login = False
        self._flagged_honeypots = set()
        self._action_log = []
        self._session_token = None
        self._config_fetched = False
        self._hidden_endpoints_found = set()
        self._low_priv_login = False

        # Build endpoint lookup
        self._endpoint_map = {e.path: e for e in self._task.endpoints}

        # Build initial observation -- endpoints are HIDDEN
        port_list = ", ".join(str(p.port) for p in self._task.ports)

        if self._task.task_id == "easy_recon":
            # Easy task: no endpoints, just ports
            targets_info = f"Ports: {port_list}\nEndpoints: N/A (port scan task only)"
        else:
            # Medium/Hard: endpoints are hidden behind ports
            targets_info = (
                f"Ports: {port_list}\n"
                f"Endpoints: UNKNOWN -- scan ports to discover web endpoints"
            )

        intro = (
            f"[ENVIRONMENT INITIALIZED]\n"
            f"Task: {self._task.description}\n"
            f"Difficulty: {self._task.difficulty}\n"
            f"Budget: {self._budget_remaining} actions\n\n"
            f"[OBJECTIVE]\n{self._task.objective}\n\n"
            f"[KNOWN TARGETS]\n"
            f"{targets_info}\n\n"
            f"[AVAILABLE ACTIONS]\n"
            f"- scan <port>: Scan a port for services and discover endpoints\n"
            f"- fuzz <endpoint>: Send probe requests to a discovered endpoint\n"
            f"- inject_payload <endpoint>: Attempt SQL injection on an endpoint\n"
            f"- login <username:password>: Attempt authentication with credentials\n"
            f"- analyze <target>: Deep probe -- check status, get profile (user:pass), or query restricted endpoint (with payload)\n"
            f"- fetch_config <target>: Retrieve config files (robots.txt, config) to discover hidden paths"
        )

        return RedVeilObservation(
            observation_text=intro,
            budget_remaining=self._budget_remaining,
            task_id=self._task.task_id,
            task_description=self._task.description,
            milestones_reached=[],
            done=False,
            reward=0.0,
        )

    def step(
        self,
        action: RedVeilAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> RedVeilObservation:
        """Execute an action in the environment."""
        self._state.step_count += 1

        if self._budget_remaining <= 0:
            return self._make_observation(
                "[BUDGET EXHAUSTED] No actions remaining. Episode complete.",
                done=True,
            )

        self._budget_remaining -= 1

        self._action_log.append({
            "step": self._state.step_count,
            "action": action.action_type.value,
            "target": action.target,
        })

        if action.action_type == ActionType.SCAN:
            obs_text = self._handle_scan(action.target)
        elif action.action_type == ActionType.FUZZ:
            obs_text = self._handle_fuzz(action.target)
        elif action.action_type == ActionType.INJECT_PAYLOAD:
            obs_text = self._handle_inject(action.target, payload=action.payload)
            # Honeypot penalty: injecting a honeypot triggers IDS, costs extra budget
            target_path = action.target if action.target.startswith("/") else "/" + action.target
            ep = self._endpoint_map.get(target_path)
            if ep and ep.is_honeypot:
                self._budget_remaining = max(0, self._budget_remaining - 1)
                obs_text += "\n[IDS ALERT] Anomalous activity detected. Security response initiated."
        elif action.action_type == ActionType.LOGIN:
            obs_text = self._handle_login(action.target)
        elif action.action_type == ActionType.ANALYZE:
            obs_text = self._handle_analyze(action.target, payload=action.payload)
        elif action.action_type == ActionType.FETCH_CONFIG:
            obs_text = self._handle_fetch_config(action.target)
        else:
            obs_text = f"[ERROR] Unknown action: {action.action_type}"

        done = self._budget_remaining <= 0 or self._admin_login

        if self._task and self._task.task_id == "easy_recon":
            if len(self._identified_real_ports) >= len(self._task.real_port_ids):
                done = True

        return self._make_observation(obs_text, done=done)

    def _handle_scan(self, target: str) -> str:
        """Handle scan: noise-modeled port scan + endpoint discovery."""
        try:
            port_num = int(target)
        except ValueError:
            return f"[ERROR] Invalid port: {target}. Provide a numeric port."

        port_config = None
        for p in self._task.ports:
            if p.port == port_num:
                port_config = p
                break

        if port_config is None:
            return f"[SCAN RESULT]\nPort {port_num}: no response (host may be filtering)"

        scan_count = self._scan_counts.get(port_num, 0)
        self._scan_counts[port_num] = scan_count + 1

        result = self._noise_engine.scan_port(port_config, scan_count)
        formatted = self._noise_engine.format_scan_result(result)

        if result.status in ("open", "open|filtered") and result.confidence > 0.6:
            if port_config.is_real:
                self._identified_real_ports.add(port_num)
            else:
                self._identified_fake_ports.add(port_num)

        # PROGRESSIVE DISCOVERY: reveal endpoints hosted on this port
        # Under high noise, only a fraction of endpoints are revealed per scan
        if port_config.hosted_endpoints and result.status in ("open", "open|filtered"):
            import random
            rng = random.Random(self._state.step_count + port_num)

            candidates = [ep for ep in port_config.hosted_endpoints if ep not in self._revealed_endpoints]

            if candidates:
                # Noise level determines discovery rate: 0.0 noise = 100%, 0.5 noise = 60%
                discovery_rate = max(0.4, 1.0 - self._task.noise_level * 0.8)
                num_to_reveal = max(1, int(len(candidates) * discovery_rate))
                # On rescan, reveal different subset (seeded by step count)
                to_reveal = rng.sample(candidates, min(num_to_reveal, len(candidates)))

                newly_revealed = []
                for ep_path in to_reveal:
                    self._revealed_endpoints.add(ep_path)
                    newly_revealed.append(ep_path)

                if newly_revealed:
                    formatted += "\n\n[DISCOVERY] Web endpoints found on port " + str(port_num) + ":"
                    for ep in newly_revealed:
                        formatted += f"\n  - {ep}"
                    unrevealed_count = len(port_config.hosted_endpoints) - len(
                        [e for e in port_config.hosted_endpoints if e in self._revealed_endpoints]
                    )
                    if unrevealed_count > 0:
                        formatted += f"\n[NOTE] Scan incomplete -- {unrevealed_count} additional endpoint(s) may exist. Rescan to discover more."
                    else:
                        formatted += "\n[NOTE] Endpoint purpose is unknown. Use fuzz to investigate."

        return formatted

    def _handle_fuzz(self, target: str) -> str:
        """Handle fuzz: only works on revealed endpoints, sends real HTTP."""
        if not target.startswith("/"):
            target = "/" + target

        # Check if endpoint has been revealed by scanning
        if self._task.task_id != "easy_recon" and target not in self._revealed_endpoints:
            return (
                f"[FUZZ RESULT] {target}\n"
                f"[ERROR] Endpoint not discovered. Scan ports first to discover endpoints."
            )

        endpoint = self._endpoint_map.get(target)
        if endpoint is None:
            return f"[FUZZ RESULT] {target}\n[HTTP 404] Endpoint not found on target server."

        self._discovered_endpoints.add(target)
        self._fuzzed_endpoints.add(target)

        # Send REAL HTTP request using the endpoint's real_route
        formatted = self._deception_engine.fuzz_endpoint(endpoint)

        if endpoint.has_vulnerability and not endpoint.is_honeypot:
            self._vuln_found = True
            self._vuln_endpoint = target

        return formatted

    def _handle_inject(self, target: str, payload: str = None) -> str:
        """Handle injection: only works on discovered endpoints, real SQLi."""
        if not target.startswith("/"):
            target = "/" + target

        if self._task.task_id != "easy_recon" and target not in self._revealed_endpoints:
            return (
                f"[INJECT RESULT] {target}\n"
                f"[ERROR] Endpoint not discovered. Scan ports first."
            )

        endpoint = self._endpoint_map.get(target)
        if endpoint is None:
            return f"[INJECT RESULT] Target {target} not found."

        response_text, success, creds = self._deception_engine.inject_payload(endpoint, agent_payload=payload)

        if success:
            self._exploit_success = True
            if creds:
                self._creds_extracted = True
                self._extracted_creds = creds

        if endpoint.is_honeypot:
            self._flagged_honeypots.add(target)

        return response_text

    def _handle_login(self, target: str) -> str:
        """Handle login: sends real auth request. Requires login endpoint discovery."""
        if ":" not in target:
            return "[LOGIN RESULT] Invalid format. Use: login username:password"

        # For non-easy tasks, agent must have discovered a login endpoint first
        if self._task and self._task.task_id != "easy_recon":
            login_discovered = False
            for ep_path in self._revealed_endpoints:
                ep = self._endpoint_map.get(ep_path)
                if ep and ep.real_route == "/login":
                    login_discovered = True
                    break
            if not login_discovered:
                return (
                    "[LOGIN RESULT] No authentication endpoint discovered.\n"
                    "You must scan ports and discover a login endpoint before attempting authentication."
                )

        parts = target.split(":", 1)
        username = parts[0].strip()
        password = parts[1].strip()

        response_text, is_admin = self._deception_engine.attempt_login(username, password)

        if is_admin:
            self._admin_login = True
        elif "successful" in response_text.lower():
            self._low_priv_login = True

        return response_text

    def _handle_analyze(self, target: str, payload: str = None) -> str:
        """Handle analyze: deep probe of an endpoint with optional auth token.

        Sends requests to /api/profile (with creds) or /api/internal/db (with token).
        """
        import requests as req

        if not target.startswith("/"):
            target = "/" + target

        # Check if it's a profile request (needs username:password in target)
        if "profile" in target or (payload and ":" in target):
            # target = "username:password" for profile
            creds_str = target
            if ":" in creds_str:
                parts = creds_str.split(":", 1)
                username, password = parts[0].strip().strip("/"), parts[1].strip()
            else:
                return "[ANALYZE RESULT] For profile, use: analyze username:password"

            try:
                resp = req.get(
                    f"{VULN_APP_URL}/api/profile",
                    params={"username": username, "password": password},
                    timeout=5,
                )
                body = resp.json()
                lines = [f"[ANALYZE RESULT] /api/profile", f"[HTTP {resp.status_code}]"]

                if resp.status_code == 200 and body.get("status") == "success":
                    profile = body.get("profile", {})
                    lines.append(f"Username: {profile.get('username')}")
                    lines.append(f"Role: {profile.get('role')}")
                    lines.append(f"Session token: {profile.get('session_token', 'N/A')}")

                    if profile.get("session_token"):
                        self._session_token = profile["session_token"]
                        lines.append("[TOKEN ACQUIRED] Use this token for restricted endpoints.")
                else:
                    lines.append(body.get("message", "Request failed."))

                return "\n".join(lines)
            except req.RequestException as e:
                return f"[ANALYZE RESULT] Connection failed: {str(e)[:100]}"

        # Analyze with token -- for restricted endpoints like /api/internal/db
        if payload and self._session_token:
            try:
                resp = req.get(
                    f"{VULN_APP_URL}/api/internal/db",
                    params={"q": payload, "token": self._session_token},
                    timeout=5,
                )
                body = resp.json()
                lines = [f"[ANALYZE RESULT] /api/internal/db", f"[HTTP {resp.status_code}]"]

                if resp.status_code == 200:
                    data = body.get("data", [])
                    if data:
                        lines.append(f"Query returned {len(data)} record(s):")
                        for item in data:
                            if isinstance(item, dict):
                                content = item.get("content", "")
                                lines.append(f"  [{item.get('category', '?')}] {content}")
                                # Check if admin creds are in the restricted data
                                if ":" in content and any(
                                    w in content.lower() for w in ("admin", "root")
                                ):
                                    parts = content.split(":", 1)
                                    self._creds_extracted = True
                                    self._extracted_creds = {
                                        "username": parts[0].strip(),
                                        "password": parts[1].strip(),
                                    }
                    else:
                        lines.append("No data returned.")
                else:
                    lines.append(body.get("message", "Access denied."))

                return "\n".join(lines)
            except req.RequestException as e:
                return f"[ANALYZE RESULT] Connection failed: {str(e)[:100]}"

        # Generic analyze -- hits /api/status?verbose=true for info disclosure
        try:
            resp = req.get(f"{VULN_APP_URL}/api/status", params={"verbose": "true"}, timeout=5)
            body = resp.json()
            lines = [f"[ANALYZE RESULT] /api/status", f"[HTTP {resp.status_code}]"]

            debug = body.get("debug", {})
            if debug:
                lines.append(f"Database tables: {', '.join(debug.get('database_tables', []))}")
                lines.append(f"Active sessions: {debug.get('active_sessions', 0)}")
                internal_eps = debug.get("internal_endpoints", [])
                if internal_eps:
                    lines.append(f"Internal endpoints: {', '.join(internal_eps)}")
                    for ep in internal_eps:
                        self._hidden_endpoints_found.add(ep)
                auth = debug.get("auth_method", "")
                if auth:
                    lines.append(f"Auth method: {auth}")
                self._config_fetched = True
            else:
                lines.append(f"Server: {body.get('server', 'unknown')}")
                lines.append(f"Uptime: {body.get('uptime', 'unknown')}")

            return "\n".join(lines)
        except req.RequestException as e:
            return f"[ANALYZE RESULT] Connection failed: {str(e)[:100]}"

    def _handle_fetch_config(self, target: str) -> str:
        """Handle fetch_config: retrieve configuration files like robots.txt.

        Can discover hidden endpoints that aren't on any port.
        """
        import requests as req

        target = target.strip().lower()

        if target in ("robots.txt", "/robots.txt", "robots"):
            try:
                resp = req.get(f"{VULN_APP_URL}/robots.txt", timeout=5)
                lines = [f"[CONFIG RESULT] /robots.txt", f"[HTTP {resp.status_code}]"]
                lines.append(resp.text)
                self._config_fetched = True

                # Parse disallowed paths as hidden endpoints
                for line in resp.text.split("\n"):
                    if line.startswith("Disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            self._hidden_endpoints_found.add(path)

                return "\n".join(lines)
            except req.RequestException as e:
                return f"[CONFIG RESULT] Connection failed: {str(e)[:100]}"

        if target in ("config", "/api/config", "api/config"):
            try:
                resp = req.get(f"{VULN_APP_URL}/api/config", timeout=5)
                body = resp.json()
                lines = [f"[CONFIG RESULT] /api/config", f"[HTTP {resp.status_code}]"]
                config = body.get("config", {})
                lines.append(f"Version: {config.get('version', '?')}")
                lines.append(f"Environment: {config.get('environment', '?')}")
                endpoints = config.get("endpoints", [])
                if endpoints:
                    lines.append("Registered endpoints:")
                    for ep in endpoints:
                        lines.append(f"  - {ep.get('path', '?')}: {ep.get('description', '?')}")
                self._config_fetched = True
                return "\n".join(lines)
            except req.RequestException as e:
                return f"[CONFIG RESULT] Connection failed: {str(e)[:100]}"

        return f"[CONFIG RESULT] Unknown config target: {target}. Try: robots.txt, config"

    def _make_observation(self, obs_text: str, done: bool) -> RedVeilObservation:
        milestones = self._get_reached_milestones()
        reward = self._compute_reward()

        budget_info = f"\n\n[STATUS] Budget remaining: {self._budget_remaining}/{self._task.budget}"
        if milestones:
            budget_info += f"\n[PROGRESS] Milestones: {', '.join(milestones)}"
        if self._revealed_endpoints:
            budget_info += f"\n[DISCOVERED ENDPOINTS] {', '.join(sorted(self._revealed_endpoints))}"
        if self._hidden_endpoints_found:
            budget_info += f"\n[HIDDEN PATHS FOUND] {', '.join(sorted(self._hidden_endpoints_found))}"
        if self._session_token:
            budget_info += f"\n[SESSION] Active token acquired"

        full_text = obs_text + budget_info

        return RedVeilObservation(
            observation_text=full_text,
            budget_remaining=self._budget_remaining,
            task_id=self._task.task_id,
            task_description=self._task.description,
            milestones_reached=milestones,
            done=done,
            reward=reward,
        )

    def _get_reached_milestones(self) -> list:
        milestones = []

        if self._task.task_id == "easy_recon":
            if self._scan_counts:
                milestones.append("scanned_port")
            if len(self._identified_real_ports) >= 1:
                milestones.append("identified_1_real")
            if len(self._identified_real_ports) >= 2:
                milestones.append("identified_2_real")
            if (len(self._identified_real_ports) >= 3 and
                    len(self._identified_fake_ports) == 0):
                milestones.append("identified_all_3_clean")

        elif self._task.task_id == "medium_deception":
            if self._discovered_endpoints:
                milestones.append("discovered_endpoint")
            if self._vuln_found:
                milestones.append("found_real_vuln")
            if self._exploit_success:
                milestones.append("exploited_vuln")
            if self._exploit_success and self._flagged_honeypots:
                milestones.append("flagged_honeypot")

        elif self._task.task_id == "hard_chain":
            if self._scan_counts or self._discovered_endpoints:
                milestones.append("useful_recon")
            if self._config_fetched:
                milestones.append("found_config")
            if self._vuln_found:
                milestones.append("found_real_vuln")
            if self._exploit_success:
                milestones.append("exploited_vuln")
            if self._creds_extracted:
                milestones.append("extracted_creds")
            if self._admin_login:
                milestones.append("admin_login")

        elif self._task.task_id == "expert_chain":
            if self._scan_counts or self._discovered_endpoints:
                milestones.append("useful_recon")
            if self._config_fetched or self._hidden_endpoints_found:
                milestones.append("info_disclosure")
            if self._low_priv_login:
                milestones.append("low_priv_access")
            if self._session_token:
                milestones.append("acquired_token")
            if self._creds_extracted:
                milestones.append("extracted_admin_creds")
            if self._admin_login:
                milestones.append("admin_login")

        return milestones

    def _compute_reward(self) -> float:
        milestones = self._get_reached_milestones()
        if not milestones or not self._task:
            return 0.0

        reward = 0.0
        milestone_rewards = {name: val for name, val in self._task.milestones}
        for m in milestones:
            if m in milestone_rewards:
                reward = max(reward, milestone_rewards[m])

        return round(reward, 2)

    @property
    def state(self) -> State:
        return self._state

    def get_game_state(self) -> dict:
        return {
            "task_id": self._task.task_id if self._task else None,
            "budget_remaining": self._budget_remaining,
            "budget_total": self._task.budget if self._task else 0,
            "scan_counts": dict(self._scan_counts),
            "revealed_endpoints": list(self._revealed_endpoints),
            "discovered_endpoints": list(self._discovered_endpoints),
            "fuzzed_endpoints": list(self._fuzzed_endpoints),
            "identified_real_ports": list(self._identified_real_ports),
            "identified_fake_ports": list(self._identified_fake_ports),
            "vuln_found": self._vuln_found,
            "vuln_endpoint": self._vuln_endpoint,
            "exploit_success": self._exploit_success,
            "creds_extracted": self._creds_extracted,
            "admin_login": self._admin_login,
            "flagged_honeypots": list(self._flagged_honeypots),
            "config_fetched": self._config_fetched,
            "hidden_endpoints_found": list(self._hidden_endpoints_found),
            "session_token_acquired": self._session_token is not None,
            "low_priv_login": self._low_priv_login,
            "milestones": self._get_reached_milestones(),
            "reward": self._compute_reward(),
            "action_log": self._action_log,
        }
