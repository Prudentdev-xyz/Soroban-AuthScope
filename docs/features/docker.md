# Non-root container for the offline AuthScope CLI

Build the multi-stage image using the pinned Node 22 image and committed npm
lockfile:

```sh
docker build -f deploy/docker/Dockerfile -t authscope:local .
```

The runtime contains only the CLI and production dependencies, runs as uid
1000 (`node`), and needs no host Docker socket, private keys or privileged
permissions. Mount previously saved authorization JSON **read-only**:

```sh
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount type=bind,src="$PWD/fixtures",dst=/input,readonly \
  authscope:local inspect /input/simulation.json --json

docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount type=bind,src="$PWD/fixtures",dst=/input,readonly \
  authscope:local diff /input/before.json /input/after.json --json
```

On Linux the mounted directory and JSON must be readable by uid 1000.
Docker Desktop and user-namespace remapping may require adjusting mount
permissions. No network is available at runtime (`--network none`).
This image intentionally does **not** include the opt-in RPC capture utility.

With local Docker installed, `bash deploy/docker/smoke.sh` creates its own
authentic SDK-XDR (but **synthetic**) fixtures, builds the image and checks
nonroot identity, help, version, valid inspection, unchanged/changed diff,
and missing input. The image is local only; nothing is published to a registry.
