# Checkmarx One Multi-Tool — activity agent (containerized run).
#
# The preferred substrate for multi-day runs: `agent run` builds and starts this
# automatically when docker/podman is available and you choose --container. The scheduling loop lives inside the process;
# the container platform supplies "keep it running" via --restart.
#
# Build:
#   docker build -t cxone-agent .
#
# Run (credentials as env vars — never bake them into the image):
#   docker volume create cxone-agent-state
#   docker run -d --name cxone-agent --restart=unless-stopped \
#     -e CXONE_BASE_URL=https://deu.ast.checkmarx.net \
#     -e CXONE_TENANT=my_tenant \
#     -e CXONE_API_KEY=<key> \
#     -e CXONE_AGENT_UNTIL=2026-07-28 \
#     -e TZ=America/Chicago \
#     -v cxone-agent-state:/state \
#     cxone-agent
#
# Review activity:  docker logs -f cxone-agent
# Stop:             docker stop cxone-agent
#
# Notes:
#  - TZ matters: business-hours weighting uses container-local time. When you
#    start the agent via `agent run --container`, the launcher auto-detects the
#    host timezone (DST-aware IANA zone) and forwards it — no need to set TZ.
#    For a raw `docker/podman run` like the example above, set -e TZ=Area/City
#    yourself, or activity will cluster around UTC office hours.
#  - /state holds the agent's private ledger (.agent_state.json) — its cadence
#    memory — and its committed plan (.agent_plan.json), which a restart resumes
#    instead of discarding. The named volume preserves both across image upgrades.
#  - Multi-identity: secondary API keys arrive as CXONE_IDENTITIES_JSON via a
#    transient --env-file at launch (never baked into the image; see
#    .dockerignore). Without it the agent runs as the primary identity only.
#  - Upgrades: `agent run --container` version-labels the image and rebuilds it
#    automatically when the installed skill version differs, then replaces the
#    container. A manually built image should pass
#    --label cxone.multitool.version=$(cat VERSION) to participate.
#  - The agent idles (does not exit) past CXONE_AGENT_UNTIL, so restart policies
#    don't loop; `docker stop` when done, or update the env and recreate to extend.
#  - Default CMD is --live. For a no-op trial run first:
#      docker run --rm -e ... cxone-agent            # would act (default --live)
#      docker run --rm -e ... cxone-agent --seed 7   # (any args replace CMD)
#      docker run --rm -e ... --entrypoint python cxone-agent \
#        multitool.py agent run --process             # DRY-RUN (no --live)

FROM python:3.12-slim

# tzdata so TZ=<area/city> shapes business-hours timing correctly.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/ ./scripts/
COPY config/ ./config/
COPY VERSION ./VERSION

# Non-root; /state is the ledger volume (CXONE_STATE_DIR is read by agent.py).
RUN useradd --create-home --uid 10001 agent \
 && mkdir -p /state \
 && chown -R agent:agent /state /app
USER agent
ENV CXONE_STATE_DIR=/state \
    PYTHONUNBUFFERED=1
VOLUME ["/state"]

WORKDIR /app/scripts
ENTRYPOINT ["python", "multitool.py", "agent", "run", "--process"]
CMD ["--live"]
