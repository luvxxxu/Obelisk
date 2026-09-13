# Obelisk

UDP 위에서 직접 동작하는 실시간 양방향 통신 프로토콜의 **상세 설계 저장소**입니다.

- [설계 개요와 확정 범위](docs/obelisk-protocol-plan.md)
- [전송·패킷·연결 상태](docs/spec/01-transport.md)
- [그룹 E2EE·기기 승인·복구](docs/spec/02-security.md)
- [중계 서비스·공개 API](docs/spec/03-service.md)
- [검증 및 출시 기준](docs/spec/04-verification.md)

현재 버전은 `1-draft.1`입니다. 프로토콜 구현, 암호 검증, 독립 상호운용, 성능 측정은 아직 수행하지 않았습니다. 프로덕션 배포 가능한 구현물로 표시하지 않습니다.

문서와 고정 형식 벡터의 일관성 검사:

```sh
bun tools/check-spec.ts
```

외부 패키지 설치는 필요하지 않습니다. 검사는 9개 정상·28개 비정상 형식 벡터와 문서/레지스트리 일치 검사를 포함합니다. AEAD 인증·Noise·MLS의 보안 검증을 대체하지 않습니다.
