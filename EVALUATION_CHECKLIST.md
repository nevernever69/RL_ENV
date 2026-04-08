# RedVeil - Evaluation Checklist

## Pre-Submission Checklist (all must pass or you're disqualified)

- [ ] **HF Space deploys** — Automated ping to Space URL must return 200 and respond to reset()
  - Status: NOT DONE
  - This is the only blocker. Everything else passes.

- [x] **OpenEnv spec compliance** — openenv.yaml, typed models, step()/reset()/state()
  - openenv.yaml: redveil/openenv.yaml (spec_version: 1, name: redveil, runtime: fastapi)
  - Typed models: RedVeilAction(Action), RedVeilObservation(Observation) in redveil/models.py
  - step(): redveil/server/redveil_environment.py:218
  - reset(): redveil/server/redveil_environment.py:127
  - state(): redveil/server/redveil_environment.py:670 (@property)
  - All 3 endpoints verified working via HTTP: POST /reset, POST /step, GET /state

- [x] **Dockerfile builds** — Automated docker build on submitted repo
  - Dockerfile: redveil/server/Dockerfile
  - Tested: builds successfully, container starts, /health returns 200
  - Full flow tested: reset -> step -> step -> state all work in Docker

- [x] **Baseline reproduces** — inference.py runs without error and produces scores
  - Tested with gpt-4o (avg=0.39) and gpt-4.1-mini (avg=0.33)
  - All 4 tasks complete without errors
  - Scores output in structured format

- [x] **3+ tasks with graders** — Enumerate tasks, run each grader, scores in 0.0-1.0
  - 4 tasks: easy_recon, medium_deception, hard_chain, expert_chain
  - All graders return 0.0-1.0 (clamped with max())
  - Partial progress signals via milestones

- [x] **Mandatory env vars**
  - API_BASE_URL: inference.py line 39 — os.getenv("API_BASE_URL", "https://api.openai.com/v1")
  - MODEL_NAME: inference.py line 40 — os.getenv("MODEL_NAME", "gpt-4o-mini")
  - HF_TOKEN: inference.py line 41 — os.getenv("HF_TOKEN") or os.getenv("API_KEY") or os.getenv("OPENAI_API_KEY")

- [x] **inference.py at project root** — /home/never/just/inference.py

- [x] **OpenAI Client for all LLM calls**
  - from openai import OpenAI (line 27)
  - client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY) (line 209)
  - client.chat.completions.create() for all inference (line 143)

- [x] **[START]/[STEP]/[END] structured logs**
  - [START] task_id={task_id} | budget={budget}
  - [STEP] step={n} | action={action} | target={target} | budget_before={budget}
  - [END] task_id={task_id} | score={score} | steps={n} | milestones={list}
  - WARNING: Haven't verified against official sample script. Any deviation = wrong scoring.


## Evaluation Criteria (page 7 of PDF)

- [x] **Runtime correctness** — Runs without errors
  - Verified: inference.py completes all 4 tasks without crashes
  - Docker container runs and serves all endpoints

- [x] **Interface compliance** — Follows OpenEnv standard
  - Uses openenv.core.env_server.interfaces.Environment base class
  - Uses openenv.core.env_server.types.Action, Observation, State
  - Uses openenv.core.env_server.http_server.create_app()
  - openenv.yaml present with correct spec_version

- [x] **Task design** — Clear, realistic, testable
  - Real-world cybersecurity task (not games or toys)
  - 4 difficulty tiers: easy -> medium -> hard -> expert
  - Real SQL injection against live SQLite database
  - WAF, honeypots, base64 encoding, information chains
  - Randomized endpoint paths prevent memorization

- [x] **Grading logic** — Reward system makes sense
  - Milestone-based partial credit (4-6 milestones per task)
  - Honeypot penalty reduces score (0.05 per hit, 1.5x on expert)
  - All scores clamped to 0.0-1.0 range
  - Graders in redveil/grader.py


## Key Requirements (page 3)

- [x] Must simulate a real-world task (not games or toys)
- [x] Implement full OpenEnv spec: typed models, step()/reset()/state(), openenv.yaml
- [x] Minimum 3 tasks with agent graders (easy -> medium -> hard, scores 0.0-1.0)
- [x] Meaningful reward function with partial progress signals
- [x] Baseline inference script with reproducible scores
- [ ] Deploy to Hugging Face Spaces + working Dockerfile
- [x] README with environment description, action/observation spaces, setup instructions


## Risk: [START]/[STEP]/[END] Format

The PDF says: "Any deviation in field names, ordering, or formatting will result in incorrect evaluation scoring. Refer to the Sample Inference Script."

Our current format:
```
[START] task_id=easy_recon | budget=6
[STEP] step=1 | action=scan | target=80 | budget_before=6
[END] task_id=easy_recon | score=1.0 | steps=3 | milestones=scanned_port,identified_1_real
```

We have NOT seen the official sample inference script. If their format uses different field names or ordering, we lose points silently. Should find and verify this before submitting.


## Baseline Scores

### gpt-4o
```
easy_recon:       1.00
medium_deception: 0.15
hard_chain:       0.30
expert_chain:     0.12
average:          0.39
```

### gpt-4.1-mini
```
easy_recon:       1.00
medium_deception: 0.15
hard_chain:       0.05
expert_chain:     0.12
average:          0.33
```


## TODO Before Submission (April 8, 11:59 PM)

1. [ ] Deploy to HF Spaces (MANDATORY — will be disqualified without this)
2. [ ] Find and verify [START]/[STEP]/[END] format against official sample
