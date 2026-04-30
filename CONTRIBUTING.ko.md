# mcp-gate 기여 가이드

[🇺🇸 English](./CONTRIBUTING.md) · 🇰🇷 한국어

mcp-gate에 기여해 주셔서 감사합니다. mcp-gate는 자격 증명을 다루는 도구이므로, 변경 사항은 [ARCHITECTURE.ko.md](./ARCHITECTURE.ko.md)에 설명된 보안 경계를 유지해야 하며 리뷰하기 쉬워야 합니다.

## PR을 열기 전에

새 기능, 보안 모델 변경, 저장 형식 변경, 새 의존성 추가처럼 사소하지 않은 변경은 먼저 이슈를 열어 주세요. 오타 수정, 문서 개선, 범위가 명확한 테스트, 명확한 버그 수정은 바로 pull request로 보내셔도 됩니다.

## 개발 환경

요구사항:

- Go 1.23 이상
- macOS 또는 Linux
- npm 패키징과 Node 호환성 smoke test를 위한 Node.js 18 이상

```bash
git clone https://github.com/seoo2001/mcp-gate
cd mcp-gate
make build
make test
make cover
make e2e
```

CI는 모든 push와 pull request에 대해 macOS와 Linux에서 `go vet`, `go test -race`, 빌드를 실행합니다.

## 유용한 명령

```bash
make build   # ./bin/mcp-gate 빌드
make test    # go test -race -count=1 ./... 실행
make vet     # go vet ./... 실행
make fmt     # go fmt ./... 실행
make e2e     # 자격 증명 격리를 검증하는 서브프로세스 E2E 실행
```

Node 프록시 호환성은 다음 명령으로 확인할 수 있습니다.

```bash
./scripts/smoke-node.sh
```

## 환영하는 기여

- 회귀 테스트가 포함된 버그 수정
- 번역을 포함한 문서 개선
- MCP 서버 런타임 호환성 개선
- `internal/services/services.go`의 새 내장 서비스 매핑 추가와 가능한 경우 테스트
- 자격 증명 격리를 약화하지 않는 감사 로그 또는 승인 흐름 개선

## 설계 논의가 필요한 변경

- 볼트 형식, 암호화, 서명, 키 파생 관련 변경
- 신뢰 저장소 또는 로컬 CA 동작 변경
- 프록시 토큰 형식 또는 검증 의미 변경
- 자격 증명 처리 경로의 새 의존성 추가
- 멀티유저, 팀, 원격 볼트 동작
- 위협 모델 경계에 영향을 주는 변경

## 코드 가이드라인

- PR을 보내기 전에 `go fmt ./...`와 `go vet ./...`를 실행해 주세요.
- 동작 변경에는 테스트를 추가해 주세요.
- PR은 하나의 논리적 변경에 집중해 주세요.
- 의존성에는 명확한 이점과 제한된 보안 영향이 있어야 하며, 가능한 경우 Go 표준 라이브러리를 우선해 주세요.
- 에러는 `%w`로 감싸고 유용한 맥락을 포함해 주세요.
- 평문 자격 증명, 프록시 토큰, 개인정보, Authorization 헤더 전체 값은 로그에 남기지 마세요.
- 주석은 명확하지 않은 이유나 보안상 중요한 결정을 설명할 때 사용해 주세요.

## 커밋과 PR 스타일

Conventional Commit 스타일 prefix를 권장하지만 필수는 아닙니다.

- `feat(scope): ...`
- `fix(scope): ...`
- `docs(scope): ...`
- `test(scope): ...`
- `chore: ...`

PR 본문에는 짧은 동기, 사용자에게 보이는 동작 변화, 실행한 테스트를 포함해 주세요.

## 보안 제보

취약점은 공개 이슈로 제보하지 말아 주세요. 재현 단계, 영향도, 영향을 받는 버전 또는 커밋, 가능하다면 수정 제안을 포함해 GitHub 프로필에 등록된 이메일로 메인테이너에게 연락해 주세요.

## 행동 강령

토론에서는 서로를 존중하고, 구체적으로 말하며, 기술적 근거에 집중해 주세요.
