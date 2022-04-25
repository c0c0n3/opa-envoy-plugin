Debug Playground
----------------
> endless fun!

So here's my set up to explore the plugin's guts.

* A Docker Compose env with Envoy in it---other services like Keycloak
  to be added later.
* Envoy is configured with a GRPC AuthZ filter that connects to port
  9191 on localhost---i.e. outside of Docker.
* OPA Envoy Plugin runs on `localhost:9191`.

You've got to run the OPA process in the repo root dir with these
args

```console
./opa_envoy_darwin_amd64 run --server \
--set=plugins.envoy_ext_authz_grpc.addr=:9191 \
--set=decision_logs.console=true \
--log-format=json-pretty \
internal/oidc/debug/policy/
```

Then bring up the Docker Compose services and test a policy deny
decision

```console
curl -v localhost:8000/
...
HTTP/1.1 403 Forbidden
...
```

as well as a policy allow decision

```console
curl -v localhost:8000/yes
...
HTTP/1.1 503 Service Unavailable
...
```

You get a `503` because there's no upstream service at the moment
Envoy can forward the request too after Plugin authorises it.

With this set up I can easily debug/edit the plugin code.
Here's the VS Code debug config I'm using

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "server",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program": "${workspaceFolder}/cmd/opa-envoy-plugin",
            "args": [
                "run",
                "--server",
                "--set=plugins.envoy_ext_authz_grpc.addr=:9191",
                "--set=decision_logs.console=true",
                "--log-format=json-pretty",
                "internal/oidc/debug/policy/"
            ],
            "cwd": "${workspaceFolder}"
        }
    ]
}
```
