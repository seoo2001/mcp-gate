# Node.js MCP 서버 호환성

[🇺🇸 English](./NODE_COMPAT.md) · 🇰🇷 한국어

## 요약

많은 Node.js HTTP 클라이언트는 `HTTPS_PROXY`를 자동으로 사용하지 않습니다. mcp-gate에서는 이 점이 중요합니다. 감싸진 MCP 서버의 업스트림 API 호출이 로컬 mcp-gate 프록시를 지나야 자격 증명 교체가 일어나기 때문입니다.

Node 기반 MCP 서버에는 다음 형태를 사용해 주세요.

```bash
mcp-gate wrap --service=github --node-shim npx -y @modelcontextprotocol/server-github
```

`--node-shim`은 작은 의존성 없는 CommonJS shim을 자식 프로세스에 로드하여, 일반적인 Node HTTP 경로가 mcp-gate가 설정한 프록시를 사용하도록 합니다.

## 호환성 매트릭스

`./scripts/smoke-node.sh` smoke test는 다음 경로를 점검합니다.

| HTTP stack | `--node-shim` 없음 | `--node-shim` 있음 |
|---|---|---|
| `node:https.request` | 직접 연결하며 `HTTPS_PROXY`를 무시합니다. | mcp-gate 프록시를 사용합니다. |
| `globalThis.fetch` / undici | dispatcher를 설정하지 않으면 직접 연결합니다. | shimmed fetch wrapper를 통해 mcp-gate 프록시를 사용합니다. |
| `undici.fetch({ dispatcher })` | 애플리케이션이 proxy dispatcher를 직접 제공한 경우에만 동작합니다. | mcp-gate가 테스트하는 shimmed 경로를 통해 계속 동작합니다. |

이 때문에 Node MCP 서버에는 `--node-shim` 사용을 권장합니다.

## Shim 동작

`--node-shim`이 설정되면 wrapper는 임시 CommonJS 파일을 만들고 자식 프로세스를 다음 환경 변수로 시작합니다.

```text
NODE_OPTIONS=--require=<shim>
```

shim은 다음 작업을 수행합니다.

1. `https.globalAgent`를 `HTTPS_PROXY`로 HTTP `CONNECT` 터널을 여는 커스텀 agent로 교체합니다.
2. 비 TLS HTTP 타깃을 위해 `http.globalAgent`도 교체합니다.
3. native fetch가 같은 프록시 경로를 사용하도록 `globalThis.fetch`를 감쌉니다.

shim은 `tls`, `net`, `http`, `https` 같은 Node built-in만 사용합니다. npm 의존성이 필요하지 않습니다.

## 커버되는 경로

`--node-shim`은 다음 경로를 대상으로 합니다.

- raw `node:https`와 `node:http`
- `globalThis.fetch`
- Node의 global HTTP(S) agent를 사용하는 많은 `axios`, `node-fetch`, Octokit 호출 경로
- 내부적으로 위 HTTP 경로를 사용하는 일반적인 `@modelcontextprotocol/server-*` 패키지

모든 Node 네트워크 경로를 커버하지는 않습니다. 특히 다음 경로는 별도 처리가 필요할 수 있습니다.

- 자체 `undici.Dispatcher`를 만들고 사용하는 코드는 `globalThis.fetch`를 우회할 수 있습니다.
- HTTP/2 전용 클라이언트는 `https.Agent`를 우회할 수 있습니다.
- WebSocket과 EventSource 스트림은 현재 자격 증명 교체 모델의 범위 밖입니다.

서버가 이런 경로를 사용한다면 해당 서버에서 명시적인 프록시 통합이 필요할 수 있습니다.

## 로컬 검증

다음 명령을 실행해 주세요.

```bash
./scripts/smoke-node.sh
```

이 스크립트는 mcp-gate를 빌드하고, 임시 볼트를 만들고, Node smoke helper를 `--node-shim` 유무에 따라 감싼 뒤, 어떤 HTTP 경로가 프록시를 사용했는지 보고합니다.

Node.js 18 이상에서 `--node-shim`이 켜져 있으면 다음 성공 지표가 포함되어야 합니다.

- `fetch_default_used_proxy`
- `raw_https_used_proxy`

## 자체 Shim을 포함하는 이유

`https-proxy-agent`는 일반적인 npm 솔루션이지만, mcp-gate는 사용자가 이를 전역 설치하거나 `npx` 패키지의 격리된 dependency tree 안에서 사용할 수 있게 만들도록 요구하지 않습니다. 또한 shim을 mcp-gate 바이너리에 포함하면 자격 증명 처리 경로에 런타임 의존성을 추가하지 않을 수 있습니다.

shim은 wrap 세션 동안 임시 파일로 기록되며 wrapper가 종료될 때 제거됩니다.

## Keep-Alive 동작

shim은 요청마다 하나의 연결을 사용합니다. 이전 keep-alive 동작에서는 일부 CONNECT 터널 응답이 응답 본문 종료 후에도 열린 상태로 남아, 대기 중인 사용자 코드가 완료되지 않을 수 있었습니다.

로컬 프록시는 같은 프로세스의 loopback 경로에 있으므로 추가 로컬 핸드셰이크 비용은 작습니다. mcp-gate 프록시는 별도로 업스트림 연결 재사용을 사용할 수 있습니다.

## `--node-shim`을 생략할 수 있는 경우

다음 경우에는 `--node-shim`을 설정하지 않아도 됩니다.

- 감싸는 자식 프로세스가 Node.js 프로세스가 아닌 경우
- 서버가 proxy-aware undici dispatcher 또는 HTTP agent를 이미 직접 설정하는 경우
- 직접 네트워크 동작을 의도적으로 테스트하는 경우

일반적인 Node MCP 서버에는 `--node-shim` 사용을 권장합니다.
