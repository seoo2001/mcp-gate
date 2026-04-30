# 아키텍처

[🇺🇸 English](./ARCHITECTURE.md) · 🇰🇷 한국어

## 개요

mcp-gate는 MCP 서버를 위한 로컬 자격 증명 볼트이자 HTTPS 프록시입니다. 현재 아키텍처는 macOS와 Linux에서의 단일 사용자 로컬 개발 환경을 중심으로 설계되어 있습니다.

1. 실제 자격 증명을 암호화된 로컬 볼트에 저장합니다.
2. MCP 서버를 자식 프로세스로 실행합니다.
3. 자식 프로세스에는 짧게 유지되는 프록시 토큰만 전달합니다.
4. 자식 프로세스의 트래픽을 로컬 프록시로 라우팅합니다.
5. 지정된 업스트림 API 요청을 전달할 때만 프록시 토큰을 실제 자격 증명으로 교체합니다.

이 설계는 MCP 서버나 그 의존성이 침해될 수 있다고 가정합니다. 로컬 OS 계정이나 mcp-gate 프로세스 자체가 침해된 상황까지 방어한다고 가정하지는 않습니다.

## 요청 흐름

```text
MCP 클라이언트
   |
   | stdio
   v
감싸진 MCP 서버
   env: GITHUB_TOKEN=mcpgate_github.<random>.<exp>.<sig>
   env: HTTPS_PROXY=http://127.0.0.1:<port>
   env: SSL_CERT_FILE=$MCP_GATE_HOME/ca.pem
   |
   | 로컬 프록시를 통한 HTTPS
   v
mcp-gate proxy
   프록시 토큰 검증
   볼트에서 실제 자격 증명 로드
   지정된 헤더 값 교체
   감사 이벤트 기록
   |
   | 실제 자격 증명이 포함된 HTTPS
   v
업스트림 API
```

감싸진 MCP 서버는 `GITHUB_TOKEN`처럼 해당 서비스가 기대하는 환경 변수에 서비스별 프록시 토큰을 받습니다. 실제 자격 증명은 프록시가 지정된 업스트림 요청을 처리하기 전까지 볼트에 남아 있습니다.

## 구성 요소

| 구성 요소 | 역할 |
|---|---|
| CLI | `add`, `wrap`, `import`, `setup`, `logs`, `services` 같은 명령을 처리합니다. |
| Wrapper | MCP 서버를 자식 프로세스로 실행하고 프록시, 신뢰 저장소, 서비스 토큰 환경 변수를 주입합니다. |
| Proxy | HTTP 프록시 트래픽을 처리하고, CONNECT 요청에 대해 로컬 TLS 인터셉션을 수행하며, 프록시 토큰 검증과 자격 증명 교체 후 업스트림으로 요청을 전달합니다. |
| Vault | `$MCP_GATE_HOME/vault.json`에 서비스 자격 증명을 envelope 암호화로 저장합니다. |
| Keystore | 볼트 마스터 키를 macOS Keychain 또는 파일 fallback에서 저장하거나 불러옵니다. |
| Service registry | 서비스 이름을 환경 변수, 토큰 prefix, 업스트림 호스트 패턴과 매핑합니다. |
| Audit log | 프록시된 요청마다 `$MCP_GATE_HOME/audit.jsonl`에 JSONL 이벤트를 기록합니다. |
| Approval gate | 선택적으로 민감한 요청을 Slack 승인 콜백이 허용할 때까지 차단합니다. |

## Wrapper 환경 변수

mcp-gate는 감싸진 프로세스마다 다음 값을 설정합니다.

- `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`를 로컬 프록시 URL로 설정합니다.
- loopback 호스트를 위해 `NO_PROXY`, `no_proxy`를 설정합니다.
- `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`를 생성된 로컬 CA 인증서 경로로 설정합니다.
- `GITHUB_TOKEN` 같은 서비스 자격 증명 환경 변수에는 짧게 유지되는 프록시 토큰을 설정합니다.
- `--node-shim`이 켜져 있으면 `NODE_OPTIONS=--require=<shim>`을 설정합니다.

mcp-gate는 CA를 시스템 신뢰 저장소에 설치하지 않습니다. 신뢰 범위는 환경 변수를 통해 감싸진 자식 프로세스로 제한됩니다.

## Proxy 동작

프록시는 `127.0.0.1`에서 수신하며 보통 OS가 할당한 포트에 바인딩합니다. HTTPS 요청의 경우 `CONNECT`를 받아들이고, 로컬 mcp-gate CA가 서명한 호스트별 leaf 인증서를 발급한 뒤, 내부 HTTP 요청을 읽고 모든 요청 헤더에서 `mcpgate_` 프록시 토큰을 찾습니다.

자격 증명 교체 규칙은 다음과 같습니다.

- 프록시 토큰이 없으면 요청을 passthrough 트래픽으로 전달하고 감사 로그를 남깁니다.
- 알 수 없는 업스트림 호스트에 프록시 토큰이 있으면 요청을 거부합니다.
- 토큰이 잘못되었거나, 만료되었거나, 다른 wrap 세션에서 서명되었거나, 다른 서비스용이면 요청을 거부합니다.
- 한 요청에 여러 프록시 토큰이 있으면 모두 같은 값이어야 합니다.
- 검증에 성공하면 요청 헤더의 해당 프록시 토큰을 모두 볼트의 실제 자격 증명으로 교체합니다.

프록시는 Go 표준 라이브러리의 네트워킹 및 TLS 기능을 사용합니다. 자격 증명을 다루는 경로를 감사하기 쉽도록 구현 범위를 작게 유지하고 있습니다.

## Vault 형식

볼트는 `$MCP_GATE_HOME/vault.json`에 저장되는 line-stable JSON 파일입니다. 각 레코드는 envelope 암호화를 사용합니다.

```text
실제 자격 증명
   |
   v
레코드별 random DEK로 AES-256-GCM 암호화
   |
   v
암호화된 값

DEK
   |
   v
마스터 키로 AES-256-GCM 암호화
   |
   v
암호화된 DEK
```

서비스 이름은 additional authenticated data로 사용됩니다. 따라서 JSON 파일에서 서비스 키를 바꾸면 해당 레코드를 열 때 인증이 실패합니다.

영구 상태는 제한된 권한으로 기록됩니다.

- `$MCP_GATE_HOME`은 `0700` 모드로 생성됩니다.
- `vault.json`, `audit.jsonl`, `ca.key`, 파일 keystore fallback은 `0600` 모드로 기록됩니다.

## Keystore 백엔드

| 백엔드 | 사용 시점 | 참고 |
|---|---|---|
| macOS Keychain | macOS에서 사용 가능할 때 기본값 | `security` CLI를 통해 볼트 마스터 키를 저장합니다. |
| File keystore | macOS 외 플랫폼의 기본값이며 macOS fallback | `$MCP_GATE_HOME/master.key`에 마스터 키를 `0600` 권한으로 저장합니다. |

`MCP_GATE_KEYSTORE=file` 또는 `MCP_GATE_KEYSTORE=keychain`으로 백엔드를 강제할 수 있습니다.

## 프록시 토큰 형식

프록시 토큰은 HMAC으로 서명되며 현재 `mcp-gate wrap` 프로세스에서만 유효합니다.

```text
mcpgate_<service>.<rand24>.<exp_unix>.<sig>
```

필드:

- `service`: `github` 같은 canonical service 이름입니다.
- `rand24`: 24바이트 랜덤 값을 padding 없는 base64url로 인코딩한 값입니다.
- `exp_unix`: Unix 만료 timestamp입니다.
- `sig`: `HMAC-SHA256(signingKey, "<service>|<rand24>|<exp_unix>")`를 padding 없는 base64url로 인코딩한 값입니다.

서명 키는 wrap 세션마다 메모리에서 생성되며 영구 저장되지 않습니다. 기본 TTL은 5분이고, 허용되는 최대 TTL은 60분입니다.

## Service Registry

내장 레지스트리는 `internal/services/services.go`에 있습니다. 각 서비스 항목은 다음 값을 정의합니다.

- canonical service 이름
- 감싸진 자식 프로세스에 설정할 환경 변수
- import/setup discovery에 사용할 선택적 환경 변수 alias
- 더 안전한 자격 증명 분류에 사용할 선택적 토큰 prefix
- 해당 서비스로 인식할 업스트림 호스트 패턴

사용자는 `$MCP_GATE_HOME/services.json`으로 서비스 정의를 추가하거나 덮어쓸 수 있습니다.

## Audit Log

감사 로그는 `$MCP_GATE_HOME/audit.jsonl`의 append-only JSONL 파일입니다. 이벤트에는 timestamp, service, method, host, path, outcome, status, duration, approval status, 비밀이 아닌 proxy-token identifier가 포함됩니다.

감사 이벤트에는 평문 자격 증명이 포함되면 안 됩니다. 프록시는 토큰의 random 필드에서 파생한 token ID만 기록하고, Authorization 헤더 전체 값은 기록하지 않습니다.

## Node.js 호환성

많은 Node.js HTTP 스택은 기본적으로 `HTTPS_PROXY`를 따르지 않습니다. Node 기반 MCP 서버의 경우 `mcp-gate wrap --node-shim`이 의존성 없는 임시 CommonJS shim을 만들고 `NODE_OPTIONS=--require=<shim>`으로 로드합니다.

호환성 매트릭스와 검증 방법은 [docs/NODE_COMPAT.ko.md](./docs/NODE_COMPAT.ko.md)를 참고해 주세요.

## 현재 제약

- Windows 네이티브 바이너리는 아직 배포하지 않습니다. Windows 사용자는 WSL2를 사용해야 합니다.
- 볼트는 단일 사용자 로컬 상태이며, 팀 또는 멀티유저 자격 증명 서비스가 아닙니다.
- 파일 keystore fallback은 실수로 인한 평문 노출을 줄이지만, OS 기반 키 저장소와 같은 수준의 보호를 제공하지는 않습니다.
- 장시간 실행되는 서버의 토큰 갱신은 감싸진 서버가 자격 증명을 다시 읽을 수 있는지에 따라 달라집니다. 이는 런타임 전반에 걸친 portable contract가 아닙니다.
- WebSocket과 EventSource 스트림은 현재 자격 증명 교체 모델의 범위 밖입니다.
