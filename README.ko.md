# mcp-gate

[![CI](https://github.com/seoo2001/mcp-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/seoo2001/mcp-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

[🇺🇸 English](./README.md) · 🇰🇷 한국어

mcp-gate는 MCP 서버를 위한 로컬 자격 증명 볼트이자 HTTPS 프록시입니다. 장기 API 자격 증명이 MCP 서버 프로세스에 들어가지 않도록 하고, 감싼 서버에는 짧게 유지되는 프록시 토큰만 전달합니다. mcp-gate는 업스트림 API 요청을 전달할 때만 해당 프록시 토큰을 실제 자격 증명으로 교체합니다.

> **상태:** 알파 버전입니다. 평가 및 로컬 개발 워크플로에는 사용할 수 있지만, CLI 세부 동작과 저장 형식은 아직 변경될 수 있습니다.

## 위협 모델

mcp-gate는 MCP 서버, 의존성, 도구 런타임이 침해될 수 있다는 가정을 기준으로 설계되었습니다. 2026년 4월 MCP 보안 보고서에서는 원격 코드 실행으로 이어질 수 있는 STDIO/config 경로가 다뤄졌고, 생태계 감사에서는 공개 MCP 서버 상당수가 방치되었거나 가볍게만 유지 관리되고 있다는 점이 지적되었습니다. 이런 환경에서는 `mcp.json`과 `.env` 파일의 평문 토큰이 높은 가치의 공격 대상이 됩니다.

관련 배경은 [The Register](https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/), [The Hacker News](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html), [Rapid Claw MCP reliability report](https://rapidclaw.dev/blog/mcp-servers-dead-what-it-means-2026)를 참고하실 수 있습니다.

mcp-gate는 다음 방식으로 자격 증명 노출을 줄입니다.

- 실제 자격 증명을 암호화된 로컬 볼트에 저장합니다.
- 자식 MCP 서버에는 기본 5분 TTL의 HMAC 서명 프록시 토큰만 전달합니다.
- 업스트림 요청을 전달하기 전에 프록시에서 토큰 만료를 강제합니다.
- 가로챈 호출을 로컬 JSONL 감사 로그에 기록합니다.

mcp-gate는 로컬 OS 계정 침해, mcp-gate 프로세스에 대한 디버거 접근, 악의적인 업스트림 API 제공자까지 방어하지는 않습니다.

## 동작 방식

```text
[MCP 서버] -- 프록시 토큰 --> mcp-gate proxy -- 실제 자격 증명 --> api.github.com
                                        |
                                        v
                               암호화된 로컬 볼트
```

MCP 서버는 실제 자격 증명을 받지 않습니다. mcp-gate는 서버를 자식 프로세스로 실행하고, 서비스별 프록시 토큰을 환경 변수에 주입한 뒤, 자식 프로세스의 트래픽을 로컬 HTTPS 프록시로 라우팅합니다. 이후 각 프록시 토큰을 검증하고, 지정된 업스트림 API 호스트로 향하는 요청에 한해서만 실제 자격 증명으로 교체합니다.

## 설치

```bash
# npm 패키지 (무관한 `mcpgate` 패키지와 이름 충돌을 피하려고 scoped 이름 사용)
npm install -g @seoo2001/mcp-gate

# 전역 설치 없이 실행
npx -y @seoo2001/mcp-gate --help

# 소스에서 빌드
git clone https://github.com/seoo2001/mcp-gate
cd mcp-gate
make build
```

npm 패키지는 Node.js 18 이상이 필요하며 macOS(arm64/x64)와 Linux(x64/arm64)용 사전 빌드 바이너리를 포함합니다. Windows 네이티브 바이너리는 아직 배포하지 않습니다. 현재 Windows 사용자는 WSL2에서 mcp-gate를 실행해 주세요.

## 빠른 시작

실제 자격 증명을 볼트에 저장합니다.

```bash
mcp-gate add github --stdin
# GitHub 토큰을 붙여 넣고 Enter를 누르세요.
```

MCP 서버를 감싸서 실행합니다.

```bash
mcp-gate wrap --service=github --node-shim npx -y @modelcontextprotocol/server-github
```

대부분의 Node.js HTTP 클라이언트는 기본적으로 `HTTPS_PROXY`를 따르지 않으므로, Node.js 기반 MCP 서버에는 `--node-shim` 사용을 권장합니다. 런타임이 프록시 환경 변수를 이미 따르는 비 Node 서버에서는 생략할 수 있습니다.

`mcp.json`에서는 전역 설치된 `mcp-gate` 바이너리를 사용할 수 있습니다.

```json
{
  "mcpServers": {
    "github": {
      "command": "mcp-gate",
      "args": [
        "wrap",
        "--service=github",
        "--node-shim",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ]
    }
  }
}
```

또는 mcp-gate 자체도 `npx`로 실행할 수 있습니다.

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "-y",
        "@seoo2001/mcp-gate",
        "wrap",
        "--service=github",
        "--node-shim",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ]
    }
  }
}
```

## 주요 명령

| 명령 | 용도 |
|---|---|
| `mcp-gate add <service> --stdin` | 셸 기록에 남기지 않고 자격 증명을 저장합니다. |
| `mcp-gate import --dry-run` | 볼트를 변경하지 않고 알려진 MCP 설정과 `.env` 위치를 스캔합니다. |
| `mcp-gate services` | 내장 서비스 매핑과 업스트림 호스트 패턴을 확인합니다. |
| `mcp-gate logs --since=24h` | 최근 24시간 동안 가로챈 호출을 확인합니다. |
| `mcp-gate info` | 볼트, 감사 로그, CA 인증서, 서비스 오버라이드 경로를 출력합니다. |

내장 서비스 매핑은 개발 도구, 생산성 도구, 인프라, 관측성, AI API 등에서 자주 쓰이는 서비스를 포함합니다. 매핑을 추가하거나 덮어쓰려면 `$MCP_GATE_HOME/services.json`을 사용하고, `mcp-gate services`로 활성 레지스트리를 확인해 주세요.

## 프로젝트 상태

현재 범위는 macOS와 Linux에서의 단일 사용자 로컬 개발입니다. 핵심 자격 증명 격리 보장은 end-to-end 테스트로 확인합니다.

> 실제 자격 증명은 감싸진 자식 프로세스의 환경 변수, 감사 로그, 볼트 파일, 그 밖의 디스크 상태에 나타나지 않습니다. 지정된 업스트림 요청을 전달할 때 mcp-gate 내부에서만 사용됩니다.

| 영역 | 상태 |
|---|---|
| 암호화된 로컬 볼트 | 구현되었습니다 |
| 프로세스 래퍼와 프록시 토큰 형식 | 구현되었습니다 |
| Authorization 헤더 교체를 수행하는 HTTPS 프록시 | 구현되었습니다 |
| 토큰 TTL 강제와 감사 로그 | 구현되었습니다 |
| Node.js 프록시 호환 shim | 구현되었습니다 |
| 민감한 경로를 위한 Slack 승인 웹훅 | 구현되었습니다 |
| Windows 네이티브 릴리스 | 예정입니다 |

## 빌드와 테스트

```bash
make build   # ./bin/mcp-gate
make test    # go test -race -count=1 ./...
make cover   # 커버리지 리포트
make e2e     # 자격 증명 격리를 검증하는 서브프로세스 E2E
```

CI는 모든 push와 pull request에 대해 macOS와 Linux에서 `go vet`, `go test -race`, 빌드를 실행합니다.

## 문서

| 파일 | 내용 |
|---|---|
| [ARCHITECTURE.ko.md](./ARCHITECTURE.ko.md) | 토큰 흐름, 프록시 동작, 보안 경계를 설명합니다. |
| [docs/NODE_COMPAT.ko.md](./docs/NODE_COMPAT.ko.md) | Node.js MCP 서버 프록시 호환성과 `--node-shim`을 설명합니다. |
| [CONTRIBUTING.ko.md](./CONTRIBUTING.ko.md) | 개발 환경, 기여 가이드, PR 규칙을 설명합니다. |

## 기여

이슈와 pull request를 환영합니다. 사소하지 않은 기능 작업, 보안 모델 변경, 의존성 추가를 시작하기 전에는 먼저 이슈를 열어 설계를 논의해 주세요. 오타, 문서 개선, 집중된 테스트처럼 작은 수정은 바로 PR로 보내셔도 좋습니다.

## 보안 제보

취약점은 공개 이슈로 등록하지 말아 주세요. 재현 방법, 영향도, 가능하다면 수정 제안을 포함해 GitHub 프로필에 등록된 이메일로 메인테이너에게 연락해 주세요.

## 라이선스

mcp-gate는 [MIT License](./LICENSE)로 배포됩니다.
