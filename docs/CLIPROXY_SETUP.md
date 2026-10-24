# Local CLIProxyAPI and Codex setup

This documents the operator-authorized local setup used on 2026-10-24. The repository contains no credential, account cache or automatic login. [The gateway](../openshield/gateway.py) remains the only inference path. [Current measurements](lab/NEXT_WAVE_RESULTS.md) distinguish valid model decisions, degraded cases and deterministic control effects.

## Installed component and boundary

The separate Windows process uses **CLIProxyAPI 8.0.41**, [commit 8289ec4c71ad914d0612c2776352b76ba3d355a6](https://github.com/router-for-me/CLIProxyAPI/tree/8289ec4c71ad914d0612c2776352b76ba3d355a6). Its [Windows amd64 release archive](https://github.com/router-for-me/CLIProxyAPI/releases/download/v8.0.41/CLIProxyAPI_8.0.41_windows_amd64.zip) was verified against the release asset SHA-256:

```text
81bba2e24e2979741a7d224164b7d3aa4bc53f38704e46cab1f10ad8dc877bd7
```

This verifies agreement with the publisher's captured release metadata, not an independent security audit of the executable. The upstream uses the [MIT license](https://github.com/router-for-me/CLIProxyAPI/blob/8289ec4c71ad914d0612c2776352b76ba3d355a6/LICENSE); no upstream implementation is vendored into Shield.

The installation lives outside the repository under `$env:LOCALAPPDATA\OpenShieldAI\CLIProxyAPI`. Its private directory ACL grants the current Windows user and SYSTEM access. The operator-generated proxy client key, YAML configuration and upstream-managed OAuth records stay there. Shield receives only the proxy client key through its named environment variable. No Codex access/refresh token was copied from the original Codex cache; the operator completed CLIProxyAPI's separate device OAuth flow.

The [pinned configuration layout](https://github.com/router-for-me/CLIProxyAPI/blob/8289ec4c71ad914d0612c2776352b76ba3d355a6/config.example.yaml) binds the listener to **127.0.0.1:8317**, requires a distinct client key, caps incoming bodies at 65,536 bytes, disables LAN discovery, management/control-panel access, request/debug logging and profiling. Private operational/error logs still belong to the upstream process; do not publish them as benchmark evidence. OAuth storage protection is the upstream/local-host boundary, not Shield's production encrypted secret broker.

The process is started explicitly, without a machine-startup task or public exposure. Its supported login is:

```powershell
$proxyRoot = Join-Path $env:LOCALAPPDATA 'OpenShieldAI\CLIProxyAPI'
& (Join-Path $proxyRoot '8.0.41\cli-proxy-api.exe') -config (Join-Path $proxyRoot 'config.yaml') -codex-device-login -no-browser -local-model
```

Complete the displayed device authorization in your own browser. This command does not copy another application's credential cache. [Official OpenAI authentication guidance](https://learn.chatgpt.com/docs/auth) describes ChatGPT login and the sensitivity of cached credentials. A model listed by the proxy is a catalog entry; a completed inference is required to establish access for that request. The proxy's reported upstream identity is not independently attested by Shield.

## Run an explicit comparison

After starting the proxy and authorizing Codex, use a model alias actually listed by that local route. The captured trial selected `gpt-6.1-sol`; the domain code does not hardcode it. The following values apply only to the current shell/child process:

```powershell
$proxyRoot = Join-Path $env:LOCALAPPDATA 'OpenShieldAI\CLIProxyAPI'
$env:SHIELD_LLM_PROVIDER='cliproxyapi'
$env:SHIELD_LLM_BASE_URL='http://127.0.0.1:8317/v1'
$env:SHIELD_LLM_MODEL='your-listed-codex-alias'
$env:SHIELD_LLM_ALLOW_LOOPBACK_HTTP='true'
$env:SHIELD_LLM_API_KEY_ENV='SHIELD_CLIPROXY_API_KEY'
$env:SHIELD_CLIPROXY_API_KEY=(Get-Content -LiteralPath (Join-Path $proxyRoot 'client-key.txt') -Raw).Trim()
$env:SHIELD_LLM_GLOBAL_TOKEN_LIMIT='192000'
python -m openshield next-wave-lab --with-ai --output output/next-wave-real-ai.json
Remove-Item Env:SHIELD_CLIPROXY_API_KEY
```

The 192,000 ceiling is a run-wide conservative reservation for visible input/output, not actual billed tokens or an account-wide spending limit. The canonical per-episode bounds remain eight calls, 64,000 reserved tokens, 180 seconds, two read rounds and a 20-second absolute call deadline. Proxy-hidden usage and subscription limits are outside that reservation. Ordinary CI and `next-wave-lab` without `--with-ai` make no provider calls.

The next-wave command first measures owned fixture effects, freezes its 16-case public engineering corpus, then compares baseline/AI using identical accepted facts, source roles, tools and **zero mutation capabilities**. Model failures, invalid output, repeated evidence requests and exhausted budgets remain degraded cases; fallback decisions are never credited as successful AI. No prompt/completion text or credential is exported. Proposed action acceptability and required-code presence are narrow registered checks, not general semantic correctness or analyst-time savings.
