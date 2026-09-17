# Obelisk/1-draft.0 프로토콜 명세

문서 상태: 설계 명세 초안
발행일: 2026-09-17
정규 표기: `Obelisk`
정규 URI 스킴: `ob://`

> 이 문서는 Obelisk의 규범적 설계 명세다. 구현체, 상호운용성 시험, 침투 시험, 암호 설계 독립 감사 또는 운영 준비 완료를 뜻하지 않는다. 특히 ML-DSA의 TLS/DTLS 서명 방식은 이 문서 발행 시점에 표준화 진행 중인 의존성이므로, 실제 배포 전에는 해당 의존성의 최종 표준과 구현체 상호운용성을 다시 동결하고 검증해야 한다.

## 1. 목적과 경계

Obelisk는 순수 UDP 위에서 동작하는 고속 양방향 전송 프로토콜이다. 전송 계층은 다음과 같다.

```text
IP → UDP → DTLS 1.3 → Obelisk/1-draft.0 → Application Profile
```

Obelisk Core는 메시지의 의미, 계정, 방 권한, 그룹 멤버십, 저장, 푸시 알림, MLS 상태를 해석하지 않는다. 그런 정책은 모두 Application Profile의 책임이다. 이 경계 덕분에 Core는 일반 실시간 채팅, 서버 간 통신, 게임 상태 갱신, 사설 RPC에 사용할 수 있고, 미래의 MLS 최적화 프로토콜도 Core 위에 별도 프로파일로 구축할 수 있다.

### 1.1 보장하는 것

- 모든 Obelisk 애플리케이션 바이트는 의도한 통신 종단 사이의 DTLS 1.3으로 기밀성·무결성·재전송 방지를 받는다.
- 신뢰할 수 있는 순서 보장 스트림, 신뢰할 수 있는 비순서 원자 메시지(RMSG), 최신 값 우선의 비신뢰성 데이터그램을 한 연관(association)에서 제공한다.
- 손실 복구, 흐름 제어, 혼잡 제어, ECN, 경로 MTU 발견을 명시적으로 수행한다.
- 일반 클라이언트는 두 개의 비공모 릴레이 도메인을 통과할 수 있다. 릴레이는 최종 애플리케이션 평문이나 C↔S DTLS 키를 보지 못한다.
- 서버 간 직접 연결은 중간 릴레이 없이 성립할 수 있다.

### 1.2 의도적으로 하지 않는 것

- HTTP/3, QUIC, WebTransport, WebSocket을 전송 기반으로 사용하지 않는다.
- 브라우저에서 원시 UDP 소켓을 제공한다고 주장하지 않는다. 브라우저는 별도 Application Profile의 HTTPS 게이트웨이를 사용한다.
- Core가 디스크 기반 오프라인 큐, 정확히 한 번의 영구 부작용, 계정 인증 정책, MLS 키 관리, 그룹 멤버십을 제공하지 않는다.
- UDP가 제공하지 않는 신뢰성·혼잡 제어를 DTLS가 자동으로 제공한다고 가정하지 않는다.
- 두 릴레이의 공모, 전역 수동 관찰자, 종단 장악, 트래픽 상관 분석을 막는다고 주장하지 않는다.

### 1.3 규범 용어

`MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`는 RFC 2119/8174의 규범 의미를 가진다. 오류 코드는 사람이 읽는 원인을 싣지 않으며, 이 문서에 명시된 숫자 코드와 발생 클래스만 전송한다.

이 문서에서 `Deterministic-CBOR(X)`는 X의 정확한 raw byte sequence다. 이름 붙은 CBOR array·map X가 `SHA-384(X)`, `|| X ||`, AEAD plaintext/AAD, exporter context에 쓰이면 언제나 그 정확한 raw `Deterministic-CBOR(X)` byte sequence를 뜻하며, 메모리 객체·구현체별 재직렬화·유사한 논리 값은 허용하지 않는다.

## 2. 역할, 프로파일, 신뢰 경계

### 2.1 역할

| 역할                      | 의미                                                                                                                     |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Dialer                    | DTLS ClientHello를 먼저 보내는 종단                                                                                      |
| Acceptor                  | DTLS ClientHello를 받는 종단                                                                                             |
| C                         | 일반 클라이언트 종단                                                                                                     |
| S                         | 최종 서비스 또는 서버 종단                                                                                               |
| R1                        | 입구 릴레이. C의 IP/포트와 R2만 안다.                                                                                    |
| R2                        | 출구 릴레이. R1과 S의 서명된 후보만 안다.                                                                                |
| Realm Root                | 오프라인 신뢰 루트. 권한 위임과 비상 회전을 승인한다.                                                                    |
| Descriptor Authority      | 짧은 수명의 엔드포인트 디렉터리를 서명하는 온라인 권한자                                                                 |
| Guard/Status Authority    | 대상별 차단 및 현재 상태를 독립적으로 서명하는 권한자                                                                    |
| Ingress/Exit Grant Issuer | 각각 R1/R2만 수신자로 하는 relay-local grant를 서명하는 서로 독립적인 권한자                                             |
| Entry/Exit Permit Issuer  | 서비스의 허가 결과를 relay에 target을 드러내지 않는 짧은 split permit으로 바꾸는, 서로 독립적인 realm 공통 온라인 권한자 |
| Admission Authority       | 정확히 하나의 target Descriptor에 위임되어 credential 허용 결과를 ServiceApproval으로 서명하는 S 또는 S의 위임자         |

`Dialer`/`Acceptor`는 인증 역할이나 사용자 권한을 뜻하지 않는다. Stream ID의 개시자 비트도 이 두 전송 역할만 사용한다.

### 2.2 필수 프로파일

| 프로파일                | 사용처                                 | 필수 성질                                                            |
| ----------------------- | -------------------------------------- | -------------------------------------------------------------------- |
| Transport Core          | 모든 Obelisk 연관                      | UDP, DTLS 1.3, 프레임·복구·혼잡·흐름 제어                            |
| Direct S2S              | 구성된 서버 간 직접 연결               | 상호 ML-DSA 인증서 인증, 양방향 IdentityConfirm, 직접 경로 이동 가능 |
| Relay Privacy           | 일반 클라이언트↔서비스                 | 서로 다른 두 릴레이 도메인, 고정 경로, C↔S DTLS 평문 전달            |
| Relay Control           | C↔R1, C↔R2, R1↔R2, R2↔S admission 제어 | application data 없이 relay admission·grant·reservation만 전달       |
| Native Client Admission | 네이티브/모바일/서버 클라이언트        | DTLS exporter에 결합된 불투명 애플리케이션 인증                      |
| Browser Gateway         | 브라우저 전용 Application Profile      | HTTPS 게이트웨이가 최종 서비스 대상 암호문을 불투명 전달             |

Browser Gateway는 Core의 대체 전송이 아니다. 브라우저와 게이트웨이 사이의 HTTPS 연결은 게이트웨이에서 끝날 수 있으므로, 최종 서비스만 복호화할 내용은 반드시 애플리케이션이 별도 종단간 암호문으로 만들어야 한다. 그 암호문의 형식은 Core 밖의 Application Profile에 속한다.

### 2.3 연결 형태

```text
직접 S2S:
  A ───────────── DTLS 1.3 / Obelisk ───────────── B

두 홉 프라이버시 릴레이 데이터 경로:
  C ─ R1 ─ R2 ─ S
       ╰──── C↔S DTLS 1.3 ciphertext unchanged ────╯
```

Relay Privacy에서 R1과 R2는 UDP/IP 헤더를 새로 만들 수 있으나 C↔S DTLS 레코드의 바이트를 해독, 조각화, 병합, 재전송, ACK 생성, 수정해서는 안 된다. 입력 데이터그램 하나는 출력 데이터그램 하나에만 대응한다.

## 3. 이름, URI, 식별자

### 3.1 URI

정규 URI는 다음 문법을 따른다.

```abnf
obelisk-uri = "ob://" authority "/" opaque-path
authority    = idna-lowercase-host
opaque-path  = 1*( unreserved / pct-encoded / "/" / ":" / "@" )
```

- 입력 시 `obelisk://` 및 대소문자가 섞인 스킴은 허용할 수 있으나, 저장·표시·서명 대상 정규형은 반드시 `ob://`다.
- host는 IDNA 처리 후 소문자 ASCII A-label로 정규화한다.
- userinfo, fragment, query, 명시적 UDP 포트는 금지한다. UDP 후보와 포트는 서명된 Endpoint Descriptor에서만 얻는다.
- percent-decoding 뒤 `opaque-path`는 1~2,048 byte여야 한다. 이는 애플리케이션이 해석하는 참조값이며, 릴레이 라우팅 키나 암호 키가 아니다.

### 3.2 식별자와 시간

- `realm_id`: 16~64바이트의 불투명 난수 식별자.
- `endpoint_id`: Realm 안에서 고유한 16~64바이트의 불투명 식별자.
- `connection_instance_id`: Direct S2S dialer가 DTLS 시작 전에 새로 만드는 중복 해소용 16바이트 난수. 수락자는 이를 새로 만들지 않고 정확히 echo한다.
- `circuit_nonce`: 릴레이 회선 설정용 16바이트 난수. 데이터 패킷에는 넣지 않는다.
- `r1_boot_epoch`, `r2_boot_epoch`: 각 relay process가 시작할 때 CSPRNG로 한 번 만드는 정확히 16바이트 값. process 수명 동안 고정하며, 다음 시작에서 절대로 재사용해서는 안 된다.
- 모든 시간은 UTC Unix 초 `u64`다. 신뢰할 수 있는 현재 시간이 없으면 새 연결·재개·디렉터리 갱신을 시작해서는 안 된다.

## 4. 암호 프로파일

### 4.1 고정 암호 선택

`Obelisk/1-draft.0`은 다음 조합만 허용한다.

| 항목               | 값                                                       |
| ------------------ | -------------------------------------------------------- |
| DTLS 버전          | DTLS 1.3 (RFC 9147)                                      |
| AEAD / hash        | `TLS_AES_256_GCM_SHA384`                                 |
| 키 교환 그룹       | `SecP384r1MLKEM1024` (`0x11ED`)                          |
| 서버 인증          | ML-DSA-87 self-signed X.509 인증서 + Descriptor SPKI pin |
| 지속 ID 확인       | Ed25519 IdentityConfirm                                  |
| 디렉터리·권한 서명 | 논리적으로 분리된 Ed25519 + ML-DSA-87 이중 서명          |
| 해시               | SHA-384                                                  |
| CBOR               | Deterministic CBOR (RFC 8949)                            |
| 서명 봉투          | COSE_Sign의 동일 페이로드 이중 서명                      |

협상 과정에서 다른 DTLS 버전, 암호군, named group, 약한 키 교환, `psk_ke`, `early_data`가 선택되면 연관을 `IDENTITY_VALIDATION_FAILED` 또는 `UNSUPPORTED_VERSION`으로 끝내야 한다. 하위 호환을 위한 자동 다운그레이드는 금지된다.

모든 Core DTLS ClientHello는 ALPN protocol name으로 정확히 하나의 `ob/1`만 제시해야 하며, Acceptor는 정확히 `ob/1`만 선택해야 한다. 다른 ALPN, ALPN 누락, 선택 실패는 `UNSUPPORTED_VERSION`이다. `ob/1`은 endpoint나 서비스 종류를 표현하지 않는 공통 transport name이며, 실제 wire version은 IdentityConfirm과 SETTINGS의 `"Obelisk/1-draft.0"`으로 별도 고정된다. 모든 Core 연관은 DTLS record replay detection을 활성화해야 한다. DTLS replay window는 Obelisk의 7.3 Packet Number 중복 제거를 대체하지 않으며, 반대도 마찬가지다.

`SecP384r1MLKEM1024`는 RFC 10024에 정의되어 있으나 범용 구현체의 지원 또는 운영 상호운용성을 뜻하지 않는다. 이 명세를 구현한 제품은 출시 전에 대상 DTLS 라이브러리가 해당 그룹을 실제로 협상하는지 상호운용성 시험으로 증명해야 한다.

ML-DSA-87의 TLS/DTLS 인증서 서명 방식은 이 문서 시점에 `draft-ietf-tls-mldsa-06`에 의존한다. 이 초안의 코드포인트나 의미가 최종 RFC와 달라지면, Obelisk wire version을 재동결하고 아래의 모든 인증·재개 시험을 다시 수행해야 한다. 구현체는 임의의 사설 TLS signature-scheme를 만들어 이 공백을 메워서는 안 된다.

### 4.2 인증서와 Descriptor pin

각 서비스/직접 서버 엔드포인트는 ML-DSA-87 공개키를 담은 self-signed X.509 인증서를 제공한다. 클라이언트는 공용 Web PKI 체인이 아니라, 서명된 Endpoint Descriptor의 다음 값을 이용해 인증서를 검증한다.

1. 인증서의 SPKI SHA-384가 Descriptor의 `dtls_spki_sha384`와 정확히 같아야 한다.
2. 인증서 유효 기간, Key Usage, 알고리즘이 현재 프로파일과 일치해야 한다.
3. Descriptor의 `endpoint_id`, 버전, 유효 기간, 폐기 상태가 현재 디렉터리·Status와 일치해야 한다.
4. Relay Privacy의 C↔S ClientHello에는 SNI, endpoint ID, endpoint hash, 서비스별 ALPN, endpoint별 ticket identity를 넣어서는 안 된다. 단, DTLS `pre_shared_key` extension의 identity는 11.6이 정한 정확히 32 byte의 단회·비의미적 재개 ticket일 때만 허용한다. 이 좁은 예외는 다른 ticket 식별자, endpoint별 ticket 이름, SNI 또는 서비스별 ALPN을 허용하지 않는다. ALPN은 일반적인 `ob/1`만 사용할 수 있다.
5. Direct S2S는 Descriptor가 정확히 허용한 경우에만 SNI를 보낼 수 있다.

### 4.3 IdentityConfirm

DTLS handshake가 완료되면 각 인증이 필요한 종단은 하나의 논리 `IDENTITY_CONFIRM` frame을 보낸다. 이 frame은 일반 Obelisk Packet 안에만 넣으며 Packet Number, ACK, 손실 복구, 혼잡 제어의 대상이다. 유실된 논리 frame은 새 Packet Number와 새 DTLS record로 재전송한다. DTLS application-data의 별도 bootstrap record를 사용해서는 안 된다.

`ctx`는 다음 Deterministic CBOR 배열이다. `ctx_bytes`는 그 배열의 정확한 raw Deterministic-CBOR byte sequence를 뜻하며, 아래 hash·서명 입력에서 `ctx`라고 쓴 곳은 모두 in-memory object가 아닌 `ctx_bytes`만 뜻한다.

```text
[
  "Obelisk IdentityConfirm v1",
  wire_version,
  direction,
  authentication_role,
  realm_id,
  endpoint_id,
  endpoint_descriptor_sha384,
  dtls_version,
  cipher_suite,
  named_group,
  handshake_kind
]
```

```text
binding = DTLS-Exporter(
  "EXPORTER-Obelisk-IdentityConfirm-v1",
  SHA-384(ctx_bytes),
  48)

signature_input =
  ASCII("Obelisk IdentityConfirm signature v1") || 0x00 || ctx_bytes || binding

signature = Ed25519.Sign(identity_ed25519_private_key, signature_input)
```

`ctx`의 각 값은 다음 exact CBOR type과 값을 써야 한다: `wire_version`은 text `"Obelisk/1-draft.0"`, `direction`과 `authentication_role`은 unsigned integer, `realm_id`/`endpoint_id`/`endpoint_descriptor_sha384`는 byte string, `dtls_version`은 unsigned `u16` 값 `0xFEFC`, `cipher_suite`는 unsigned `u16` 값 `0x1302`, `named_group`은 unsigned `u16` 값 `0x11ED`, `handshake_kind`는 text다. `direction`은 `0=dialer-to-acceptor`, `1=acceptor-to-dialer`이고, `authentication_role`은 `0=service`, `1=direct-peer`, `2=relay-control`이다. `handshake_kind`는 정확히 `"full"` 또는 `"resumed"` text다. ticket을 ClientHello에 제시했는지는 기준이 아니다. ServerHello가 `pre_shared_key.selected_identity`를 실제 선택하고 `psk_dhe_ke`로 끝난 handshake만 `"resumed"`이며, PSK가 선택되지 않았거나 ticket을 거부하고 certificate handshake로 끝난 경우는 `"full"`이다. `endpoint_descriptor_sha384`는 48 byte, Ed25519 signature는 64 byte여야 한다. `realm_id`와 `endpoint_id`는 3.2의 16~64 byte 한도를 만족해야 하며, 완성된 `IDENTITY_CONFIRM` frame value는 512 byte를 넘을 수 없다. 현재 profile과 맞지 않는 enum·type·값·길이 또는 이 크기 한도 초과는 `IDENTITY_VALIDATION_FAILED`다.

`IDENTITY_CONFIRM` frame value는 definite-length 3-item Deterministic-CBOR 배열 `["OBIC/1", ctx, signature]`의 정확한 byte다. 두 번째 원소는 위의 11-item `ctx` array 자체이며 CBOR byte-string wrapper를 한 번 더 붙여서는 안 되고, 세 번째 원소 `signature`는 정확히 64 byte byte string이다. signature input의 모든 인용 label은 따옴표와 NUL delimiter를 제외한 US-ASCII byte이고, DTLS-Exporter context value는 정확히 `SHA-384(ctx_bytes)`의 48 byte다. 수신자는 현재 Descriptor의 Ed25519 공개키로 서명을 확인하고, `ctx`의 모든 필드가 실제 handshake와 현재 디렉터리 상태에 정확히 맞는지 확인한다. 이 frame의 완전 직렬화 길이는 7.1.1의 `B - 8` 안에 들어가야 한다. exporter 바이트 자체는 wire나 애플리케이션에 노출해서는 안 된다. 같은 논리 Confirm의 byte-identical retransmission은 새 Packet Number여도 다시 검증하지 않고 ACK만 생성할 수 있으며, 다른 byte의 duplicate는 `PROTOCOL_VIOLATION`이다.

- 일반 C→S: S가 먼저 Confirm을 보내고, C는 이를 검증한 뒤 `AUTH`를 보낸다. C는 Core 인증서를 보내지 않는다.
- Direct S2S: Acceptor는 `CertificateRequest`를 보내야 하며, 양쪽은 ML-DSA-87 client/server certificate를 교환하고 Descriptor pin으로 확인한다. 인증서는 self-signature, `CA=false`, `digitalSignature`, 유효 기간, `SHA-384(DER SubjectPublicKeyInfo)`까지 검증해야 한다. 그 뒤 양쪽은 새 Ed25519 IdentityConfirm을 교환해야 한다.
- 일반 C의 C↔R1 Relay-Control 및 C↔R2 Setup에서는 relay만 `authentication_role=relay-control` IdentityConfirm을 보내고 C는 relay Descriptor를 검증한다. C는 Core IdentityConfirm이나 stable endpoint Descriptor를 보내지 않으며, 뒤의 grant별 일회성 PoP로만 relay admission을 증명한다. R1↔R2 Relay Peer-Control은 Direct S2S와 같이 양방향 hybrid identity를 요구한다.
- 재개 연결도 새 IdentityConfirm을 요구한다. 재개 ticket이 본래 full handshake의 ML-DSA 검증을 계승할 수는 있지만, Descriptor·키 epoch·폐기 상태가 바뀌었으면 full handshake가 필수다.

각 exporter 사용처는 이 절에 지정된 서로 다른 label과 canonical context를 사용해야 한다. exporter 결과나 그 일부를 frame, credential, error, telemetry, log에 직접 넣어서는 안 된다.

### 4.4 세션 재개와 키 갱신

Acceptor는 full authentication을 성공한 뒤에만 32바이트 무작위의 stateful one-time ticket을 발급할 수 있다. ticket은 서버 RAM 또는 원자적 공유 메모리에만 보관하고, 서버 재시작 시 모두 무효가 된다. 한 성공 연관당 유효 ticket은 하나이며 새 ticket은 이전 ticket을 대체한다.

ticket state는 원자적으로 다음 전이를 따른다.

```text
UNUSED → PENDING → CONSUMED
```

- address-validation cookie와 PSK binder를 모두 검증한 뒤 실제 `selected_identity`로 선택한 UNUSED ticket만 `PENDING`이 된다. 이 전이는 exact ClientHello handshake message의 SHA-384, source tuple·cookie binding, DTLS handshake instance, deadline을 함께 원자적으로 보관한다.
- Client Finished가 검증된 뒤에만 `CONSUMED`가 된다.
- 현재 DTLS handshake retransmission timeout의 세 배와 10초 중 더 이른 deadline 안에 Finished가 오지 않으면 handshake state를 폐기하고 ticket을 반드시 원자적으로 `UNUSED`로 되돌린다. 이 deadline 계산의 초기 DTLS retransmission timeout은 1초다.
- `psk_dhe_ke`와 새 `SecP384r1MLKEM1024` key share만 허용한다. `psk_ke`와 0-RTT/early data는 금지하며 수신하면 폐기한다.
- `PENDING` ticket에 대해 위에 저장한 exact ClientHello hash와 source tuple·cookie binding이 같은 재전송은 state를 바꾸거나 새로 만들지 않고, 이미 만든 DTLS handshake flight만 RFC 9147에 따라 재전송한다. 다른 ClientHello, 다른 tuple, cookie/binder 불일치는 새 server state나 큰 응답을 만들지 않고 조용히 거부한다. `CONSUMED` ticket을 다시 제시한 ClientHello도 같다.

ticket 상태에는 wire version, realm ID, Endpoint Descriptor SHA-384, identity/auth epoch, DTLS 버전·암호군·그룹, 발급/만료 시각, privacy profile이 결합된다. Direct S2S ticket에는 양쪽 Descriptor hash도 결합한다. Descriptor, 인증 키, auth epoch, revocation, profile 중 하나라도 달라지면 ticket은 사용할 수 없다. 재개 때도 현재 Directory·Status·Revocation을 다시 확인하고, 새 IdentityConfirm과 요구되는 새 `AUTH`를 마친 뒤에만 데이터를 ACTIVE로 노출할 수 있다.

각 방향은 다음 중 먼저 도달하는 시점에 DTLS 1.3 KeyUpdate를 보낸다.

- 15분
- 보호된 record 1,048,576개
- 보호된 애플리케이션 payload 1 GiB

유휴 상태이면 다음 실제 패킷 직전에 갱신한다. 동시에 하나의 미확인 KeyUpdate만 허용한다. 평상시에는 `update_not_requested`, 비상 운영 절차에서만 `update_requested`를 사용한다. 어느 임계에 도달하면 송신자는 다음 새 application·Obelisk·RCT data record보다 먼저 현재 epoch로 KeyUpdate를 보낸다. 그 DTLS ACK를 받기 전에도 현재 epoch의 application·Obelisk·RCT record와 필요한 DTLS ACK는 계속 보낼 수 있지만, 새 sending key/epoch로 보호한 어떠한 record도 보내서는 안 된다. DTLS post-handshake retransmission timeout이 여섯 번 연속 만료될 때까지 ACK를 받지 못하면 `CONNECTION_TIMEOUT`으로 닫는다. KeyUpdate는 대칭 전송 키만 갱신하며 IdentityConfirm, Obelisk Packet Number, Stream ID를 다시 시작시키지 않는다. KeyUpdate의 확인은 Obelisk `ACK`가 아니라 DTLS 1.3 post-handshake `ACK`다. KeyUpdate를 보낸 종단은 그 ACK를 처리한 때에만 send epoch를 원자적으로 전환하며, 그 전에는 다음 KeyUpdate도 보내서는 안 된다. 수신자는 새 epoch로 보호된 peer record 하나를 성공적으로 복호화할 때까지 직전 read keying material을 반드시 유지해야 한다.

## 5. 발견, 디렉터리, 폐기

### 5.1 발견 절차

`ob://host/path`의 종단을 찾는 클라이언트는 다음 URL만 요청한다.

```text
https://host/.well-known/obelisk/realm/1
```

요청은 `GET`과 `Accept: application/obelisk-discovery+cbor`만 사용한다. 응답은 `200`, 정확히 `Content-Type: application/obelisk-discovery+cbor`, `Content-Encoding` 없음 또는 `identity`, 존재하는 `Content-Length`와 같은 raw body여야 하며 4 MiB를 넘으면 안 된다. redirect, cookie, client certificate, query, fragment, HTTP content compression은 금지한다. DNS와 HTTPS는 위치를 찾는 수단일 뿐 신뢰 루트가 아니다. 애플리케이션의 안전한 설정 또는 직접 배포 pin은 정규화한 `host`, 예상 `realm_id`, Realm Root 공개키 fingerprint를 함께 묶어야 하며 TOFU로 받아서는 안 된다.

발견 body는 다음 Deterministic CBOR map이어야 한다. map key는 unsigned integer, resource index는 0-based `resources[]` index다.

```text
ob-discovery/1 = {
  0: "ob-discovery/1", 1: realm_id,
  2: delegation_resource_index:uint,
  3: directory_resource_index:uint,
  4: status_resource_index:uint,
  5: resources[],
  6: consistency_proofs[],
  7: revocation_proofs[]
}

resource = [kind:uint, sha384:48, length:uint, resource_path:text]
kind = 0:RealmDelegation | 1:RealmDirectory | 2:Status |
       3:EndpointDescriptor | 4:RevocationCheckpoint |
       5:TargetedDenial | 6:Revocation
consistency_proof = [old_ledger_size:uint, checkpoint_resource_index:uint, hashes[]]
unrevoked_proof = [0, target_kind:uint, target:bytes, zero_leaf:48, siblings[384]]
revoked_proof   = [1, target_kind:uint, target:bytes, leaf_value:48, siblings[384],
                   revocation_resource_index:uint, ledger_index:uint, inclusion_hashes[]]
```

`delegation_resource_index`, `directory_resource_index`, `status_resource_index`는 각각 kind `0`, `1`, `2`의 정확히 하나의 resource를 가리켜야 한다. resource의 `resource_path`는 공백·authority·query·fragment를 포함할 수 없고, 정확히 `/.well-known/obelisk/realm/1/`로 시작하는 absolute-path여야 한다. 클라이언트는 `https://host`에 그 path만 붙여 resource를 요청한다. resource 응답도 redirect/cookie/client certificate/query/fragment 없이 `200`, `Content-Type: application/cose`, identity encoding, 선언한 raw length 및 SHA-384와 정확히 같아야 한다. hash와 length 검증은 CBOR/COSE parse와 signature 검증 전에 수행한다.

`consistency_proof`는 cached old ledger size에 맞는 하나를 사용하고 hash 배열은 48 byte 원소 최대 64개다. `revocation_proof`는 아래 5.2.1이 요구하는 각 target마다 정확히 하나여야 한다. non-revoked proof는 48 byte zero leaf만, revoked proof는 kind `6` resource·leaf value·ledger inclusion proof를 반드시 담아야 한다. root, directory, status, route가 가리키는 Descriptor, Status가 가리키는 checkpoint/모든 denial, 필요한 Revocation object는 `resources[]`에 정확히 존재해야 한다. 클라이언트는 이 bundle을 받은 뒤에도 Root→Authority 위임, COSE hybrid signature, canonical payload, 시간, 정확한 hash·length, consistency·SMT proof를 모두 검증해야 한다.

### 5.2 서명된 객체

모든 아래 payload는 Deterministic CBOR이다. 각 논리 Authority의 서명은 같은 정확한 payload 바이트에 대한 Ed25519와 ML-DSA-87의 한 쌍이어야 하며, 둘은 같은 issuer·realm·document type·`keyset_id`에 결합된다. `kid`는 해당 Authority와 key epoch를 유일하게 가리켜야 한다. Ed25519와 ML-DSA-87 서명을 서로 다른 keyset에서 섞어 검증해서는 안 된다. Directory/Descriptor는 현재 위임된 Authority 한 쌍으로, Guard·Status는 아래 5.3의 2-of-3 threshold로 서명한다.

| 객체                | 핵심 필드                                                                                                  | 규칙                                           |
| ------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Realm Delegation    | realm, authority key set, 역할, not-before/not-after                                                       | Realm Root가 서명, 짧은 수명                   |
| Realm Directory     | realm, generation, not-before, issued/expires, 활성 Descriptor의 `{endpoint_id, version, SHA-384, length}` | 정확한 Descriptor hash와 length 불일치 시 거부 |
| Endpoint Descriptor | endpoint ID/version, 후보, DTLS SPKI hash, Ed25519 키, profile, validity, key/auth epoch                   | 서비스 후보는 Descriptor에서만 권한을 얻음     |
| Status              | realm, serial, issued/expires, Revocation checkpoint 참조, Guard object 참조                               | 유효 기간은 최대 15분                          |
| Targeted Denial     | 정확한 endpoint/key epoch/descriptor hash, 범위, expiry                                                    | Guard 2-of-3, 최대 15분의 좁은 대상만 차단     |
| Revocation          | 폐기된 정확한 키·Descriptor·Authority, issued, reason code                                                 | 제거·만료로 되살아나지 않음                    |
| ServiceApproval     | realm, target Descriptor, RAE·reply key·PoP·context binding, profile, expiry                               | 해당 target에 위임된 role 7만 서명             |

### 5.2.1 Canonical CBOR payload schema

이 절의 map key는 unsigned integer이고, 표에 없는 key, duplicate key, indefinite-length CBOR, 비정규 key 순서는 금지한다. 모든 정수는 tag 없는 CBOR major type 0의 `0..2^64-1`이고 negative integer, bignum, float, tag는 허용하지 않는다. 모든 `hash`는 48 byte SHA-384이고, 모든 public key는 해당 FIPS/COSE 규격의 표준 인코딩 바이트열이다. `realm_id`와 `endpoint_id`는 definite byte string 16~64 byte, `keyset_id`는 16 byte, Ed25519 public key는 32 byte다.

모든 `*_sha384`와 `*_length`는 CBOR tag 98을 포함한 정확한 raw `COSE_Sign` CBOR byte sequence의 SHA-384와 octet length다. COSE_Sign payload는 detached가 아닌 정확한 Deterministic-CBOR byte string이고 external AAD는 empty byte string이다. 일반 객체는 같은 keyset의 Ed25519·ML-DSA-87 signature entry 정확히 두 개를, Guard/Status threshold 객체는 서로 다른 두 keyset의 hybrid pair 정확히 두 개(총 네 signature entry)를 가져야 한다. 각 signature entry의 protected header에는 정확한 `alg`, `kid`, `content type`가 있어야 하며 unprotected header에 critical parameter를 둘 수 없다. `content type`은 protected header label `3`의 text이고, 이 문서의 모든 signed object(ServiceApproval, permit, grant 포함)에서 payload map key `0`의 type text와 byte-for-byte 정확히 같아야 한다. 예를 들어 payload `0:"ob-entry-permit/1"`은 protected `content type:"ob-entry-permit/1"`만 허용한다. COSE envelope 자체는 payload를 바꾸거나 재직렬화해서는 안 된다.

각 COSE signature의 protected header에는 적어도 `alg`, `kid`, `content type`가 있어야 한다. `alg`는 keyset의 Ed25519 또는 ML-DSA-87용 COSE 알고리즘과 정확히 일치해야 하며, `kid`와 algorithm이 같은 keyset의 반대 알고리즘 signature와 짝을 이뤄야 한다. unprotected header의 critical parameter, detached payload, 임의의 재압축은 허용하지 않는다.

| 문서 type                    | 정규 payload map                                                                                                                                                                                                                                                                                |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ob-realm-delegation/1`      | `{0:type, 1:realm_id, 2:generation, 3:not_before, 4:expires, 5:authorities[]}`                                                                                                                                                                                                                  |
| `ob-directory/1`             | `{0:type, 1:realm_id, 2:generation, 3:not_before, 4:issued, 5:expires, 6:descriptor_refs[], 7:uri_routes[]}`                                                                                                                                                                                    |
| `ob-endpoint-descriptor/1`   | `{0:type, 1:realm_id, 2:endpoint_id, 3:version, 4:not_before, 5:expires, 6:key_epoch, 7:auth_epoch, 8:candidates[], 9:dtls_spki_sha384, 10:identity_ed25519, 11:profile_flags, 12:direct_sni_allowed, 13:admission_recipient?, 14:admission_authority_keyset_id?, 15:relay_privacy_domain_id?}` |
| `ob-status/1`                | `{0:type, 1:realm_id, 2:serial, 3:not_before, 4:issued, 5:expires, 6:revocation_checkpoint_ref, 7:targeted_denial_refs[]}`                                                                                                                                                                      |
| `ob-targeted-denial/1`       | `{0:type, 1:realm_id, 2:endpoint_id, 3:descriptor_hash, 4:key_epoch, 5:not_before, 6:expires, 7:reason_code}`                                                                                                                                                                                   |
| `ob-revocation/1`            | `{0:type, 1:realm_id, 2:target_kind, 3:target, 4:issued, 5:reason_code}`                                                                                                                                                                                                                        |
| `ob-revocation-checkpoint/1` | `{0:type, 1:realm_id, 2:ledger_size, 3:log_root, 4:revocation_smt_root, 5:previous_checkpoint_hash?, 6:issued, 7:expires}`                                                                                                                                                                      |

`authorities[]`의 원소는 `[role, keyset_id, ed25519_public_key, mldsa87_public_key, not_before, expires, audiences[]]`다. `role`은 `0=DescriptorAuthority`, `1=Guard`, `2=Status`, `3=IngressGrantIssuer`, `4=ExitGrantIssuer`, `5=EntryPermitIssuer`, `6=ExitPermitIssuer`, `7=AdmissionAuthority`다. role 3/4의 `audiences[]`는 해당 issuer가 grant를 발급할 수 있는 정확한 relay `endpoint_id` 목록이고, role 7의 원소는 정확히 하나의 `[endpoint_id:bytes, descriptor_sha384:48]`이다. 이 `endpoint_id`는 3.2의 길이 규칙을 만족하며 Descriptor의 bytes와 정확히 같아야 한다. role 7은 그 하나의 현재 Descriptor에 대해서만 ServiceApproval을 서명할 수 있다. role 0/1/2/5/6에서는 반드시 빈 배열이다. role 5와 role 6 keyset은 서로 달라야 하며 Relay Privacy target별·서비스별로 나눌 수 없고, 같은 realm의 모든 Relay Privacy target에 각각 공통으로 사용해야 한다. 따라서 R1이 permit signer만으로 S를 추론해서는 안 되고, 하나의 permit issuer compromise만으로 양쪽 permit을 만들 수 없다. `descriptor_refs[]`의 원소는 `[endpoint_id, version, descriptor_sha384, descriptor_length]`다. `uri_routes[]`의 원소는 `[uri_host:text, endpoint_id, version, descriptor_sha384, descriptor_length]`다. `uri_host`는 3.1의 정규 A-label이어야 하며 중복될 수 없고, 각 route는 `descriptor_refs[]`의 정확히 하나의 원소와 byte-for-byte 일치해야 한다. 입력 URI host는 정확히 하나의 route와 일치해야 하며 0개 또는 둘 이상이면 discovery 실패다. `candidates[]`의 원소는 `[ip_bytes, udp_port, priority]`이며 `ip_bytes`는 정확히 4 또는 16 byte다. hostname 재해석은 후보 대체 권한이 아니므로 Descriptor의 UDP candidate에 hostname을 넣을 수 없다.

모든 배열은 definite length이고, `authorities[]`는 최대 32, `descriptor_refs[]`와 `uri_routes[]`는 각각 최대 4,096, `candidates[]`는 최대 8, `targeted_denial_refs[]`는 최대 128이다. `descriptor_refs[]`의 endpoint ID, `uri_routes[]`의 host, `(ip_bytes, udp_port)` candidate, `(role, keyset_id)` authority는 각각 중복될 수 없다. `udp_port`는 1~65,535, `priority`는 0~255, version/generation/key epoch/auth epoch/serial/length는 unsigned integer다. Directory의 Guard와 Status role에는 각각 서로 다른 정확히 세 keyset이 있어야 하며, threshold object는 그 중 서로 다른 두 keyset의 hybrid pair만 사용한다.

`profile_flags`는 8.3의 profile flags와 같은 bit를 사용한다. `direct_sni_allowed`는 boolean이며 false일 때 Direct S2S도 SNI를 보내서는 안 된다. `target_kind`는 `0=Descriptor hash(48 byte)`, `1=SPKI hash(48 byte)`, `2=Authority keyset(16 byte)`, `3=EndpointKeyEpoch`다. kind `3`의 target은 정확한 `Deterministic-CBOR([endpoint_id, key_epoch])` byte string이다. reason code는 `0=unspecified`, `1=key compromise`, `2=misissuance`, `3=operational withdrawal`만 허용한다. `targeted_denial_refs[]`의 원소는 `[denial_sha384, denial_length]`, `revocation_checkpoint_ref`는 `[checkpoint_sha384, checkpoint_length]`이고, 각 참조는 별도 COSE object를 정확히 가리킨다.

`admission_recipient`는 Relay Privacy Descriptor에서 필수이며 `[recipient_kid:16, kem_id, aead_id, recipient_mlkem1024_public, not_before, expires]`다. `kem_id`는 정확히 `"ML-KEM-1024"`, `aead_id`는 정확히 `"AES-256-GCM"`이어야 한다. `admission_authority_keyset_id`도 Relay Privacy Descriptor에서 필수인 16 byte 값이며, 이 Descriptor와 정확히 일치하는 audience를 가진 현재 role 7 Realm Delegation을 가리킨다. 이 keyset은 S 자신일 수도, S를 위해 credential을 판정하는 위임 Admission Authority일 수도 있다. 두 field는 Descriptor 서명·유효 기간·Revocation 검증으로만 신뢰한다.

`relay_privacy_domain_id`는 relay 역할을 할 수 있어 `profile_flags`에 `0x08`을 세운 Descriptor에서 필수인 16 byte opaque 값이다. Realm Root는 실제 운영·법적·hosting·로그·key-management·관리 접근이 독립적인 relay 집합에만 서로 다른 값을 위임해야 하며, 값이 다르다는 사실만으로 독립성이 자동으로 증명되는 것은 아니다. 이 값은 C와 R1이 서로 다른 privacy domain을 기계적으로 거부하는 최소 정책 binding이다.

표에서 `?`는 해당 profile에서만 생략 가능한 field다. Relay Privacy가 설정된 Descriptor에서 `admission_recipient` 또는 `admission_authority_keyset_id`가 없거나 만료·폐기되었으면 사전 admission을 시작해서는 안 된다.

### 5.2.2 객체 크기와 파서 한도

모든 CBOR parser의 최대 nesting depth는 16이며, 발견 및 resource fetch 전체 deadline은 10초, 동시 resource fetch는 최대 8개다. 구현체는 raw size cap을 확인하기 전 nested container, certificate, key, signature, proof를 allocation·복호화·검증해서는 안 된다.

| 대상                                | 최대 raw byte |
| ----------------------------------- | ------------: |
| Discovery manifest                  |         4 MiB |
| Realm Delegation COSE               |       128 KiB |
| Realm Directory COSE                |         1 MiB |
| Endpoint Descriptor COSE            |        64 KiB |
| Status / Revocation Checkpoint COSE |     각 64 KiB |
| Targeted Denial / Revocation COSE   |     각 16 KiB |
| X.509 DER certificate               |        16 KiB |

manifest의 `resources[]`는 최대 256개이고 같은 SHA-384를 두 번 넣을 수 없다. `consistency_proofs[]`는 cached old ledger size당 최대 하나이며, `revocation_proofs[]`는 같은 `(target_kind,target)`당 정확히 하나다. 이 한도를 넘어야 하는 Realm은 조용한 pagination이나 확장을 만들지 말고 새 wire version과 새 proof 규칙을 정의해야 한다.

Targeted Denial의 `expires`는 `not_before + 900초`를 넘을 수 없다. Status의 `expires`도 `issued + 900초`를 넘을 수 없다. 반면 Revocation은 만료 필드를 갖지 않으며, 서명 권한이 단순히 최신 문서에서 생략해서 취소할 수 없다.

Status signer는 bare revocation이나 bare denial을 만들 수 없다. `targeted_denial_refs[]`는 현재 유효한 모든 Targeted Denial을 빠짐없이 열거해야 하며, 수신자는 각 object의 hash·길이·Guard 2-of-3 hybrid signature·scope·expiry를 검증한다. EndpointKeyEpoch/Descriptor/SPKI Revocation은 Guard 2-of-3 hybrid signature가 필요하고, `target_kind=Authority keyset` Revocation은 Realm Root의 hybrid signature만 허용한다.

영구 Revocation은 단순한 sparse Merkle tree만으로 append-only가 되지 않는다. 따라서 Realm은 **append-only Revocation Ledger**와 그 현재 상태를 나타내는 sparse Merkle tree를 함께 사용한다. Ledger의 `i`번째 leaf는 `L_i = SHA-384(0x00 || "Obelisk Revocation Ledger leaf v1" || revocation_cose_bytes)`다. 두 child의 parent는 `N(left,right) = SHA-384(0x01 || left || right)`다. `MTH(0)`은 `SHA-384("Obelisk Revocation Ledger empty v1")`, `MTH(1)`은 그 leaf, `MTH(n>1)`은 `n`보다 작은 최대 2의 거듭제곱 `k`로 나눈 `N(MTH(left[0:k]), MTH(right[k:n]))`다. checkpoint의 `log_root`는 정확히 `MTH(ledger_size)`여야 한다. leaf의 순서·바이트·index는 발급 뒤 바꾸거나 삭제할 수 없다.

`ob-revocation-checkpoint/1`은 Guard 2-of-3 hybrid signature로 서명한다. Authority keyset Revocation을 처음 포함하는 checkpoint는 이 Guard threshold와 해당 Revocation object의 Realm Root hybrid signature를 모두 요구한다. checkpoint의 `previous_checkpoint_hash`는 바로 앞의 같은 Realm checkpoint 전체 COSE 바이트의 SHA-384이거나, 첫 checkpoint일 때 생략한다. `expires`는 `issued + 900초`를 넘을 수 없다. 영구 Revocation이 서명되면 Guard는 60초 안에 이를 포함한 새 checkpoint를 발급해야 한다. ledger가 바뀌지 않은 경우에도 freshness를 유지하기 위해 새 checkpoint를 발급할 수 있으나, `ledger_size`, `log_root`, `revocation_smt_root`는 이전 checkpoint와 정확히 같아야 한다.

새 checkpoint를 받는 discovery 응답은 캐시된 `(old_ledger_size, old_log_root)`에서 새 `(ledger_size, log_root)`로 가는 `consistency_proof[]`를 제공해야 한다. `consistency_proof[]`는 48 byte hash의 배열이며, 위의 `L_i`와 `N`을 hash 함수로 바꾼 **RFC 9162 §2.1.4.1의 `PROOF(old_size, D_new)`**와 정확히 같은 순서·최소 node 집합이어야 한다. `0 < old_size < ledger_size`인 검증은 RFC 9162 §2.1.4.2를 그대로 사용하되 `HASH(0x01 || left || right)`를 이 명세의 `N(left,right)`로 치환한다. 특히 old size가 2의 거듭제곱이면 verifier가 old root를 proof 앞에 prepend하는 규칙을 반드시 적용한다. 다른 자체 변형 알고리즘이나 proof 순서는 허용하지 않는다.

처음 보는 Realm checkpoint는 유효한 threshold signature와 freshness를 검증한 뒤 캐시한다. 캐시가 있으면 `ledger_size`가 감소하거나 같은 크기에서 `log_root` 또는 SMT root가 달라지는 checkpoint를 거부한다. ledger size가 증가하면 위 consistency proof가 필수이고, 같으면 proof는 비어 있어야 한다. hash 길이·proof 검증·signature가 하나라도 실패하면 새 checkpoint·Status·연결을 거부한다. Status serial만 증가했다고 checkpoint를 갱신한 것으로 보아서는 안 된다. 이 규칙은 캐시를 가진 수신자에게 오래된 ledger나 다른 fork를 되돌려 주는 공격을 검출한다. 처음 접속하는 수신자와 threshold Authority가 공모하는 경우는 이 trust model 밖이며 14절의 운영 위험으로 남는다.

Status가 참조하는 checkpoint는 같은 Realm이고 유효한 Guard signature를 가지며, `checkpoint.issued <= status.issued`, `status.issued - checkpoint.issued <= 60초`, `checkpoint.expires >= status.expires`를 모두 만족해야 한다. 따라서 Status와 checkpoint는 둘 다 최대 15분 동안만 유효하고, 새 Status가 임의의 오래된 checkpoint를 다시 가리킬 수 없다. 수신자는 현재 시간이 Status와 checkpoint의 유효 기간 안에 있을 때만 새 연결 또는 ticket 재개에 사용할 수 있다.

`revocation_smt_root`는 ledger의 모든 leaf에서 유도한 현재 lookup map의 SHA-384 root다. leaf key는 `SHA-384("Obelisk Revocation SMT leaf v1" || target_kind:u8 || target)`이고, revoked leaf value는 해당 Revocation COSE object 전체 바이트의 SHA-384, 비폐기 leaf value는 48 byte zero다. internal node는 `N_smt(left,right) = SHA-384("Obelisk Revocation SMT node v1" || left:48 || right:48)`다. empty subtree는 `E_0 = 48 byte zero`, `E_(i+1) = N_smt(E_i,E_i)`로 정한다. bottom-up level `i=0..383`의 key bit는 `bit_i = (key[47-floor(i/8)] >> (i mod 8)) & 1`이며, `bit_i=0`이면 `node=N_smt(node,siblings[i])`, `1`이면 `node=N_smt(siblings[i],node)`다. `siblings[0]`은 leaf 단계이고 `siblings[383]`은 root 직전 단계다. non-revoked proof의 leaf value는 정확히 `E_0`이어야 한다.

discovery 응답은 실제로 사용할 Descriptor hash, SPKI hash, 인증에 쓴 모든 Authority keyset, 해당 Descriptor의 `EndpointKeyEpoch`마다 5.1의 `revocation_proof`를 정확히 하나 제공해야 한다. 하나라도 없거나 root·target·leaf value·COSE signature·ledger inclusion이 맞지 않으면 unrevoked로 추정하지 말고 fail-closed한다. 같은 `(target_kind,target)`에 두 번째 nonidentical Revocation을 append하는 것은 금지하며, 첫 Revocation의 raw COSE hash가 그 leaf value를 영구히 고정한다.

revoked 경우 manifest의 `revoked_proof`는 `ledger_index`와 `inclusion_hashes[]`를 제공해야 한다. `inclusion_hashes[]`는 48 byte hash 배열이고 최대 64개이며, 받은 Revocation COSE bytes에서 계산한 `L_ledger_index`를 leaf로 하여 RFC 9162 §2.1.3.1의 `PATH(ledger_index, D_ledger_size)`와 정확히 같아야 한다. verifier는 RFC 9162 §2.1.3.2를 그대로 사용하되 node hash를 이 명세의 `N(left,right)`로 치환한다. `ledger_index >= ledger_size`, 너무 길거나 짧은 path, hash 길이 오류, 계산 root 불일치는 모두 inclusion 실패다. 수신자는 checkpoint의 SMT root와 이 ledger inclusion을 모두 검증하고, COSE signature·target·leaf value까지 일치할 때만 revoked로 본다. Targeted Denial은 이 영구 ledger에 넣지 않는다.

Endpoint Descriptor 후보에는 literal IP, `udp_port`, 우선순위만 들어간다. endpoint ID, stable account ID, 릴레이 회선 ID, 사용자 credential, hostname은 후보에 넣어서는 안 된다.

### 5.3 Root, Guard, Status

- Realm Root는 Descriptor Authority, Guard, Status, IngressGrantIssuer, ExitGrantIssuer, EntryPermitIssuer, ExitPermitIssuer, AdmissionAuthority의 온라인 권한을 각각 짧은 기간으로만 위임한다. role 7 AdmissionAuthority의 delegation은 정확히 하나의 `[endpoint_id, descriptor_sha384]` audience만 가질 수 있으며, 해당 Descriptor의 `admission_authority_keyset_id`와 같아야 한다. Root와 각 Authority의 회전은 Root의 hybrid 서명과 새 키의 수락 증명이 필요하다. 비상 Root 회전은 오프라인 Root 절차와 애플리케이션의 pin 갱신을 요구한다.
- Guard는 현재 Delegation의 서로 다른 정확히 세 Guard keyset 중 둘의 hybrid 서명(즉 최소 네 개의 유효 서명)으로만 Targeted Denial 또는 EndpointKeyEpoch/Descriptor Revocation을 만든다. Guard는 특정 endpoint/key epoch/descriptor hash만 거부할 수 있고, realm 전체 또는 임의의 사용자 전체를 차단할 수 없다.
- Status signer 집합은 Directory Authority 및 Guard와 논리적으로 분리되어야 하며 2-of-3 hybrid 서명을 요구한다.
- 새 연결과 ticket 재개는 15분 이내의 유효 Status가 없으면 시작해서는 안 된다. 이미 ACTIVE인 연관은 새로 검증된 자신 대상의 Revocation 또는 Targeted Denial이 없는 한 상태 문서가 오래되었다는 이유만으로 끊지 않는다.
- Revocation은 지속적이다. 더 최신 문서가 단순히 목록에서 누락했다고 폐기가 취소되지 않는다. 같은 신원을 복구하는 대신 새 key epoch와 새 Descriptor를 발급해야 한다.
- Authority keyset을 쓰기 전 수신자는 현재 유효한 Realm Delegation에서 `role`, `keyset_id`, 두 public key, validity, audience를 모두 일치시켜야 한다. self-asserted role, grant 안의 `issuer_keyset`, 또는 Directory의 서명만으로 새 Authority 권한을 얻을 수 없다.

수신자는 cache에 `[realm_id, generation, SHA-384(raw_directory)]`, `[realm_id, serial, SHA-384(raw_status)]`, `[endpoint_id, version, SHA-384(raw_descriptor)]`를 유지한다. 이미 수용한 같은 `realm_id`의 더 낮은 Directory generation 또는 Status serial은 거부하고, 같은 generation/serial에 다른 raw hash가 오면 discovery equivocation으로 거부하며 cache를 바꾸지 않는다. 새 Directory에서 이미 수용한 endpoint ID가 다시 나오면 version을 낮출 수 없고, 같은 version은 정확히 같은 raw Descriptor여야 한다. `not_before <= issued <= expires`가 있는 모든 객체, `not_before <= expires`만 있는 객체, `revocation.issued <= checkpoint.issued`를 각각 만족하지 않으면 거부한다. duplicate CBOR key, 비정규 CBOR, 문서별 최대 길이 초과, 알 수 없는 critical field, `not-before` 이전 또는 만료 문서는 거부한다. Root 교체에는 이전 pinned Root의 hybrid 서명과 `prev_root_fingerprint` 연속성이 필요하다. 이전 Root를 잃었거나 침해된 경우의 복구는 Core wire가 아니라 out-of-band 애플리케이션 업데이트만으로 수행한다.

이 구조는 단일 Status/Revocation 서명자가 전체 서비스를 멈추게 하는 공격을 줄이지만, 다수 Authority의 공모·장악을 제거하지는 않는다.

### 5.4 후보 선택

클라이언트는 5.2.1의 `uri_routes[]`에서 정규화한 `ob://` host와 정확히 일치하는 하나의 route를 고르고, manifest kind `3` resource에서 그 route의 hash·length·endpoint ID·version과 정확히 일치하는 Descriptor를 얻어야 한다. `opaque-path`는 이 단계의 Descriptor 선택에 영향을 주지 않는다. 유효한 후보가 IPv6와 IPv4 모두 있으면 IPv6를 먼저 시도하고 250 ms 후 IPv4를 병행할 수 있다. 첫 번째로 **전체 DTLS·IdentityConfirm·정책 검증을 마친** 경로가 승자가 되며, 나머지 시도는 즉시 취소한다. 단순 UDP 응답, ICMP, 인증되지 않은 DTLS alert는 승리 조건이 아니다.

### 5.5 초기 DoS 방어

DTLS Acceptor와 Relay Setup slot은 주소 검증 전에는 cookie/HelloRetryRequest 이외의 큰 응답, ML-KEM decapsulation, ML-DSA 서명 검증, certificate 전송, ticket lookup, grant 검증, 회선 할당을 수행해서는 안 된다. ClientHello는 4 KiB 이하, cookie는 64 byte 이하이고 source IP/port와 ClientHello transcript SHA-384에 결합되며 10초 뒤 만료해야 한다. cookie 검증 전 응답은 정확히 하나의 UDP datagram 및 `min(1,200 byte, 3 × received_bytes)`를 넘을 수 없다. 인증되지 않았거나 형식이 틀린 UDP/DTLS 입력에는 자세한 close나 오류를 보내지 않고 조용히 폐기한다.

certificate chain/intermediate는 허용하지 않으며 self-signed DER certificate는 하나만, 16 KiB 이하만 허용한다. Descriptor, CBOR, certificate, signature, ticket, fragment, grant에는 5.2.2의 길이·개수와 object당 100ms, 전체 discovery transaction당 1초 CPU 시간 상한을 적용해야 한다. 이 상한을 넘는 입력은 resource state를 만들지 않고 폐기한다. 이 규칙은 정상 handshake보다 방어 우선이며, address validation 전 응답 증폭을 허용해서는 안 된다.

## 6. 연관 상태와 인증

### 6.1 상태 기계

```text
NEW → DISCOVERED → DTLS_HANDSHAKING → IDENTITY_CONFIRMING
    → SETTINGS_EXCHANGE → AUTHENTICATING? ──accepted──→ ASSOCIATION_CONFIRMING?
                                        └─rejected──→ DRAINING → CLOSED
    → ACTIVE → DRAINING → CLOSED
```

- `AUTHENTICATING`은 Native Client Admission에만 필수다.
- `ASSOCIATION_CONFIRMING`은 Direct S2S에만 필수다.
- DTLS handshake가 끝난 직후 각 방향의 Obelisk Packet Number는 0에서 시작한다. `IDENTITY_CONFIRMING`부터 `DRAINING`까지의 모든 Core 제어는 Obelisk Packet·ACK·PTO의 대상이며, 아래 표가 그 상태에서 새로 시작할 수 있는 frame을 정한다.

| 상태                     | 새로 시작할 수 있는 frame                                         |
| ------------------------ | ----------------------------------------------------------------- |
| `IDENTITY_CONFIRMING`    | `IDENTITY_CONFIRM`, `ACK`, `PING`, `PADDING`, `CONNECTION_CLOSE`  |
| `SETTINGS_EXCHANGE`      | 위 frame과 `SETTINGS`                                             |
| `AUTHENTICATING`         | 위 frame과 `AUTH`, `AUTH_RESULT`                                  |
| `ASSOCIATION_CONFIRMING` | 위 frame과 `ASSOCIATION_CONFIRM`                                  |
| `ACTIVE`                 | profile과 flow control이 허용하는 모든 registry frame             |
| `DRAINING`               | `ACK`, `PADDING`, `CONNECTION_CLOSE`, 이미 보낸 `GOAWAY`의 재전송 |

각 상태에서는 ACK되지 않은 앞선 상태의 **byte-identical 논리 frame** 재전송도 허용한다. 이는 새 상태 전이나 부작용을 만들지 않으며 새 Packet Number로만 전송한다. 이외의 새 frame, 또는 유효한 peer IdentityConfirm·양방향 SETTINGS·요구되는 AUTH·해당 profile의 ASSOCIATION_CONFIRM 이전의 STREAM/RMSG/DATAGRAM/애플리케이션 노출 제어 frame은 `PROTOCOL_VIOLATION`이다.

IdentityConfirm phase는 profile이 요구하는 모든 inbound `IDENTITY_CONFIRM`을 검증했고, 자신에게 요구된 outbound Confirm이 있다면 그 논리 frame이 peer ACK로 확인된 뒤에만 끝난다. inbound Confirm 집합이 비어 있는 profile도 가능하다. SETTINGS phase는 양쪽 logical SETTINGS를 수락했고 자신이 보낸 SETTINGS가 ACK된 뒤 끝난다. AUTH와 ASSOCIATION_CONFIRM도 각각 필요한 inbound 결과와 자신이 보낸 논리 frame의 ACK가 확인된 뒤에만 다음 phase로 넘어간다. 송신자는 자기 앞 phase가 이 조건을 만족하기 전 다음 phase의 새 frame을 보내서는 안 된다. ACK, PING, PADDING, CONNECTION_CLOSE, 그리고 byte-identical 재전송은 이 barrier의 예외다. 하나의 packet에 ACK와 그 ACK로 막 해제된 다음 phase frame이 함께 있으면 수신자는 먼저 모든 유효 ACK를 처리한 뒤 나머지 frame의 상태 적합성을 판정한다.

UDP 재정렬을 위해 수신자는 아직 prerequisite가 끝나지 않은 유효한 pre-ACTIVE `IDENTITY_CONFIRM`, `SETTINGS`, `AUTH`, `AUTH_RESULT`, `ASSOCIATION_CONFIRM`을 DTLS-authenticated bounded cache에 하나씩 보관할 수 있다. 이 cache의 총 raw frame value 한도는 4 KiB이며, cached frame은 prerequisite가 끝날 때까지 state 전이·인증 부작용·애플리케이션 노출을 만들지 않는다. 같은 logical frame의 byte-identical duplicate는 ACK만 처리하고, 다른 byte/두 번째 값/한도 초과는 `PROTOCOL_VIOLATION`이다. prerequisite가 충족되면 cached value를 phase 순서대로 정확히 한 번 처리한다. STREAM/RMSG/DATAGRAM과 다른 frame은 cache할 수 없다.

송신 ACK와 수신 허용을 구분한다. 필요한 identity/settings를 검증했고 자신의 SETTINGS를 이미 보낸 relay는 아직 SETTINGS ACK가 없더라도 다음 relay bootstrap record를 11.2.1의 제한 아래 수신할 수 있다. S가 `AUTH_RESULT=0`을 이미 보낸 뒤에는 그 결과 packet의 ACK 전에도 C의 ACTIVE frame을 수신·처리할 수 있고, Direct S2S acceptor가 정확한 `ASSOCIATION_CONFIRM` echo를 이미 보낸 뒤에도 dialer의 ACTIVE frame을 수신·처리할 수 있다. 이는 semantic prerequisite가 이미 충족된 경우에만 적용하며, outbound control packet의 ACK/loss ledger와 byte-identical 재전송 의무는 유지한다. `AUTH_RESULT=1`에는 이 예외가 없다.

이외의 새 frame, 또는 위 phase completion 이전의 STREAM/RMSG/DATAGRAM/애플리케이션 노출 제어 frame은 `PROTOCOL_VIOLATION`이다.

- `CLOSED`는 종단 상태다. 같은 UDP tuple이나 CID를 재사용해 되살릴 수 없다.

### 6.2 SETTINGS와 정책 불변성

IdentityConfirm이 끝난 뒤 각 종단은 정확히 한 개의 논리 `SETTINGS` 프레임을 보낸다. SETTINGS의 value는 Deterministic CBOR map이며 적어도 다음을 담는다.

```text
wire_version, profile_flags, max_data, max_stream_data,
max_streams_bidi, max_streams_uni, max_packet_frames,
rmsg_max_length, rmsg_max_incomplete, stream_buffer_limits
```

`wire_version`, 보안 프로파일, privacy profile, MTU 최소치, ECN 필수 여부는 SETTINGS로 협상하거나 낮출 수 없다. 양쪽 값이 이 명세와 맞지 않으면 `UNSUPPORTED_VERSION` 또는 `PROTOCOL_VIOLATION`으로 닫는다. 수신자는 처음 SETTINGS exact byte를 association 수명 동안 보관하고, byte-identical duplicate만 ACK·수락하며 다른 SETTINGS는 상태가 진행된 뒤에도 `PROTOCOL_VIOLATION`으로 닫는다. 수신 한도와 credit은 이후 `MAX_*` 프레임으로 증가만 가능하다.

### 6.3 Native Client Admission

일반 C→S 연결은 Core 인증서를 요구하지 않는다. 대신 SETTINGS 뒤 C는 한 번의 불투명 `AUTH`를 보내고, S는 `AUTH_RESULT`로 승인 또는 거부 코드만 돌려준다. Core는 credential을 해석하지 않는다.

Native Application Profile은 다음처럼 exporter를 직접 노출하지 않는 결합 증명을 요구해야 한다.

```text
auth_context = Deterministic-CBOR([
  "Obelisk AppAuth v1", realm_id, service_endpoint_id,
  service_descriptor_sha384, auth_nonce, direction, handshake_kind
])
E = DTLS-Exporter("EXPORTER-Obelisk-AppAuth-v1", SHA-384(auth_context), 48)
K = HKDF-Expand(SHA-384, E, "Obelisk AppAuth proof key v1", 48)
auth_proof_context = Deterministic-CBOR([
  "Obelisk AppAuth proof v1", auth_context, SHA-384(opaque_credential)
])
proof = HMAC-SHA-384(K, SHA-384(auth_proof_context))
```

`auth_nonce`는 C가 새로 만든 32바이트 난수이며 같은 연관에서 재사용할 수 없다. `opaque_credential`은 1~512 byte여야 한다. 더 큰 credential은 Core가 조각화하지 않으며 송신 전 local `AUTH_TOO_LARGE` 실패로 처리한다. 구체 형식과 사용자의 권한 판단은 Application Profile이 정의한다. 브라우저 Gateway Profile은 C↔S DTLS exporter를 가질 수 없으므로 이 절차를 흉내 내서는 안 된다. 대신 최종 S의 공개키에 묶인 별도 종단간 인증 envelope를 사용해야 한다.

`AUTH_RESULT.decision=0`이 양쪽에서 수락되고 ACK될 때만 `AUTHENTICATING`에서 `ACTIVE`로 전이한다. `decision=1`을 보내거나 받으면 어떤 종단도 ACTIVE로 전이하거나 애플리케이션 frame을 수락해서는 안 된다. sender는 reliable `AUTH_RESULT=1`의 ACK 뒤 별도 `CONNECTION_CLOSE(POLICY_REJECTED)`를 보내고 `DRAINING`으로, receiver는 그 결과를 ACK한 뒤 `DRAINING`으로 전이해 결국 `CLOSED`가 된다. 거부 결과가 유실되어도 9.1의 재전송을 적용하며, detail을 더 담은 close나 재인증 시도는 허용하지 않는다.

### 6.4 Direct S2S 중복 해소

동일 realm의 동일 endpoint pair에는 ACTIVE Direct S2S 연관을 하나만 유지한다. 정상적으로는 endpoint ID가 사전식으로 더 작은 종단만 dial을 시작한다. 두 연결이 동시에 유효해진 경우에는 더 작은 dialer endpoint ID를 가진 연결을 유지한다. dialer가 같은 중복 연결끼리는 dialer가 생성하고 수락자가 echo한 `connection_instance_id`의 바이트 사전식으로 더 작은 값을 유지한다. 패자는 `DUPLICATE_ASSOCIATION`으로 닫는다.

## 7. Obelisk 패킷 문법

### 7.1 UDP와 DTLS 경계

DTLS handshake가 완료된 뒤 `IDENTITY_CONFIRMING`부터 `DRAINING`까지, 하나의 Obelisk Packet은 정확히 하나의 DTLS application-data record이며 그 record는 정확히 하나의 UDP datagram의 유일한 DTLS record여야 한다. 이 규칙은 IdentityConfirm, SETTINGS, AUTH, ASSOCIATION_CONFIRM과 그 ACK·재전송에도 동일하게 적용된다.

DTLS handshake, DTLS alert, RFC 9853 RRC record, Relay Setup/Bind control record는 Obelisk Packet이 아니다. 한 UDP datagram에 여러 DTLS record를 넣거나 하나의 Obelisk Packet을 여러 UDP datagram으로 나누는 것은 금지한다. UDP/IP fragmentation도 금지한다.

DTLS full/resumed handshake, alert, post-handshake message와 RRC도 각 UDP datagram에 DTLS record 하나만 넣고, DPLPMTUD가 아직 검증되지 않은 동안에는 1,200 byte UDP payload를 넘겨서는 안 된다. `SecP384r1MLKEM1024` key share나 ML-DSA certificate처럼 큰 handshake message는 RFC 9147의 DTLS handshake fragmentation으로 여러 DTLS record/UDP datagram에 나누는 것이 필수다. Obelisk Packet의 분할 금지는 이 표준 DTLS handshake fragment에 적용되지 않는다. DTLS library가 그 fragment의 ACK·재전송을 처리하며 Obelisk Packet Number/ACK/loss recovery는 handshake fragment에 관여해서는 안 된다. IP fragmentation, 여러 record coalescing, 사설 handshake fragment 형식은 금지한다.

### 7.1.1 정확한 packet 예산

`P`는 9.4에서 정한 현재 경로·방향별 안전 UDP payload 최대치다. 즉 UDP header 뒤에서 실제로 전송되는 **완성된 하나의 DTLS record 전체 byte 길이**의 상한이며, 처음에는 1,200이다. `P`에는 DTLS record header, CID, epoch/sequence, 암호화 inner content type, AEAD tag와 Obelisk plaintext가 모두 포함된다.

각 송신 Obelisk Packet에 대해 `O`는 그 정확한 DTLS application-data record의 완성 wire length에서 ObeliskPacket plaintext length를 뺀 byte 수다. DTLS application-data record에는 Obelisk `PADDING` 외의 DTLS-level padding을 넣어서는 안 된다. 따라서 현재 CID/epoch/record 형식에서 `O`는 record header·CID·암호화 내부 type·AEAD overhead를 모두 포함한 정확한 값이다. `B = P - O`는 그 record에 넣을 수 있는 ObeliskPacket plaintext 예산이다.

송신자는 DTLS library가 제공하는 정확한 overhead 또는 동등하게 안전한 사전 계산으로 `O`를 구해야 하며, 최종 record 길이가 `P`를 넘으면 절대로 보내서는 안 된다. `ObeliskPacket`의 전체 plaintext length는 `B` 이하여야 하고, 한 frame의 직렬화 전체(`frame_type || frame_length || frame_value`)는 `B - 8` 이하여야 한다. 하나의 packet에 여러 frame을 넣을 때도 그 frame들의 직렬화 길이 합은 `B - 8` 이하여야 한다. `B`가 10 byte보다 작아 PING frame 하나와 Packet Number조차 넣을 수 없으면 경로는 `PATH_MTU_ERROR`다.

초기 `P=1,200`에서 conforming DTLS stack은 이 프로파일의 record/CID 형식으로 `B >= 1,024`를 제공해야 한다. 이를 보장하지 못하는 stack 또는 경로는 Core control을 시작하지 않고 `PATH_MTU_ERROR`로 실패한다. 이 하한은 IdentityConfirm, SETTINGS, 512 byte 이하 AUTH가 fragmentation 없이 초기 control packet에 들어갈 수 있게 하는 wire requirement다.

### 7.2 Canonical OVINT

프레임 type, length, Stream ID, RMSG ID 등 62비트 이하의 정수는 `OVINT`를 사용한다.

| 첫 2비트 | 전체 길이 | 값 비트 |
| -------- | --------: | ------: |
| `00`     |    1 byte |       6 |
| `01`     |   2 bytes |      14 |
| `10`     |   4 bytes |      30 |
| `11`     |   8 bytes |      62 |

첫 byte의 상위 2비트를 제거한 뒤 남은 바이트를 big-endian으로 읽은 값이 정수다. 값은 반드시 최소 길이로 인코딩해야 한다. 즉 `0..63`, `64..16383`, `16384..1073741823`, 그 이상 `2^62-1`까지가 각각 1/2/4/8 byte 범위다. 비최소 인코딩, `2^62` 이상 값, 잘린 값은 `FRAME_ENCODING_ERROR`다.

### 7.3 Packet과 Frame

```text
ObeliskPacket = packet_number:u64be || 1*64( Frame )
Frame          = frame_type:OVINT || frame_length:OVINT || frame_value:bytes
```

Packet Number는 송신 방향별로 0에서 시작하는 단조 증가 `u64`다. 재사용·되감기·wrap은 금지한다. 마지막 값을 보내기 전에 새 연관을 만들어야 한다. DTLS의 자체 replay protection과 Obelisk Packet Number는 서로 대체하지 않는다.

수신자는 인증·복호화 뒤 방향별 최근 4,096개 Packet Number의 sliding bitmap을 유지한다. 이미 본 번호와 window보다 오래된 번호는 frame을 다시 처리하지 않고 새 ACK도 유발하지 않는다. 새 번호가 window를 앞으로 밀면 빠진 번호는 ACK range에서 빠진 상태로 남으며, sender의 손실 복구가 처리한다.

frame type의 값에서 bit 61 (`0x2000000000000000`)은 Critical bit다. 수신자가 알 수 없는 Critical frame은 `UNSUPPORTED_CRITICAL_FRAME`으로 연관을 닫는다. 알 수 없는 non-critical frame은 `frame_length`만큼 정확히 건너뛴다. 어떤 패킷도 64개를 넘는 frame을 담을 수 없다.

각 frame grammar는 정확히 `frame_length` byte를 소비해야 한다. trailing byte, short value, 예약된 flag bit는 `FRAME_ENCODING_ERROR`다. 7.1.1의 `B`는 송신 packet 예산이므로, 수신자는 자신의 outbound `B`와 다르다는 이유만으로 인증·복호화에 성공한 peer frame을 거부해서는 안 된다.

### 7.4 프레임 레지스트리

|     값 | 이름                 | ack-eliciting | 용도                                 |
| -----: | -------------------- | ------------- | ------------------------------------ |
| `0x00` | PADDING              | 아니오        | 0으로만 채운 길이 조절               |
| `0x01` | PING                 | 예            | liveness·DPLPMTUD probe              |
| `0x02` | ACK                  | 아니오        | 수신·ECN 보고                        |
| `0x03` | CONNECTION_CLOSE     | 예            | 종단 오류 종료                       |
| `0x04` | GOAWAY               | 예            | 새 작업을 받지 않는 drain            |
| `0x05` | SETTINGS             | 예            | 초기 고정 한도·프로파일              |
| `0x06` | MAX_DATA             | 예            | 연결 신뢰성 데이터 credit 증가       |
| `0x07` | MAX_STREAM_DATA      | 예            | stream credit 증가                   |
| `0x08` | MAX_STREAMS_BIDI     | 예            | 양방향 stream 수 credit 증가         |
| `0x09` | MAX_STREAMS_UNI      | 예            | 단방향 stream 수 credit 증가         |
| `0x0a` | DATA_BLOCKED         | 예            | 연결 credit 부족 신호                |
| `0x0b` | STREAM_DATA_BLOCKED  | 예            | stream credit 부족 신호              |
| `0x0c` | STREAMS_BLOCKED_BIDI | 예            | bidi stream 수 부족 신호             |
| `0x0d` | STREAMS_BLOCKED_UNI  | 예            | uni stream 수 부족 신호              |
| `0x10` | STREAM               | 예            | 신뢰성·순서 보장 byte 범위           |
| `0x11` | RESET_STREAM         | 예            | 자신의 송신 절반 비정상 종료         |
| `0x12` | STOP_SENDING         | 예            | 상대의 송신 절반 취소 요청           |
| `0x13` | RMSG                 | 예            | 신뢰성·비순서 원자 메시지 조각       |
| `0x14` | RMSG_RECEIPT         | 예            | 애플리케이션 전달 대기열 삽입 영수증 |
| `0x15` | RMSG_ABORT           | 예            | 원자 메시지 실패                     |
| `0x16` | DATAGRAM             | 예            | 최신 값 우선 비신뢰성 데이터         |
| `0x20` | AUTH                 | 예            | 불투명 native admission envelope     |
| `0x21` | AUTH_RESULT          | 예            | 승인/거부 코드                       |
| `0x22` | ASSOCIATION_CONFIRM  | 예            | Direct S2S 활성화 확인               |
| `0x23` | IDENTITY_CONFIRM     | 예            | DTLS exporter에 결합한 endpoint 확인 |

PADDING value는 모두 `0x00`이어야 한다. PING의 value는 비어 있어야 한다. ACK만 있는 패킷과 PADDING만 있는 패킷은 ack-eliciting이 아니다. 그 외 표의 ack-eliciting frame 하나 이상을 담은 패킷은 ack-eliciting이다. 한 packet에는 ACK frame을 최대 하나만 넣을 수 있다. `CONNECTION_CLOSE`는 PADDING 외의 다른 frame과 동봉할 수 없다.

### 7.5 공통 오류 규칙

길이 불일치, 예약 비트 사용, 허용되지 않은 상태의 frame, 같은 필드의 모순 값, 한도 초과, 잘못된 canonical CBOR은 `PROTOCOL_VIOLATION` 또는 더 구체적인 오류로 닫는다. 모든 frame parser와 상태 회계는 checked arithmetic 또는 충분히 넓은 정수로 계산하고, `offset + data_length`, `offset + fragment_length`, `final_size`, credit 누적값, range endpoint를 allocation 전에 검사해야 한다. 산술 overflow/wrap 또는 frame 범위가 표현 가능한 정수 밖이면 `FRAME_ENCODING_ERROR`, flow credit 계산 overflow 또는 credit 초과면 `FLOW_CONTROL_ERROR`, stream/RMSG의 확정 범위 모순은 각각 `STREAM_STATE_ERROR`/`RMSG_LIMIT_ERROR`다. DTLS 인증 실패와 replay는 DTLS 계층에서 조용히 폐기할 수 있으며, 공격자에게 오류 oracle을 제공해서는 안 된다.

## 8. 프레임의 정확한 의미

### 8.1 ACK

```text
ACK value =
  largest_acked:u64be || ack_delay_us:u32be || range_count:u8 ||
  range_count * (start:u64be || end:u64be) ||
  ect0_count:u64be || ect1_count:u64be || ce_count:u64be
```

range는 `[start, end]`를 뜻하며 `start <= end`여야 한다. range는 큰 Packet Number부터 엄격히 내림차순이고 겹치거나 인접해서는 안 된다. `range_count`는 1 이상 64 이하이며 첫 range의 `end`는 반드시 `largest_acked`와 같아야 한다. 또한 ACK frame의 완전 직렬화 길이는 현재 outbound `B - 8` 안에 들어가야 한다. 따라서 송신자는 64개 이하의 후보 중 이 예산에 맞는 최대 개수만 넣고 largest range를 보존한 채 가장 오래된 range부터 버린다. 초기 최소 `B=1,024`에서는 ACK frame에 최대 61개 range만 들어갈 수 있다. ACK는 수신한 정확한 Obelisk Packet Number만 보고한다. 수신자가 아직 송신하지 않은 미래 Packet Number를 ACK하면 `PROTOCOL_VIOLATION`이고, 이미 송신했지만 복구 상태에서 은퇴한 너무 오래된 Packet Number는 무시할 수 있다.

ACK 송신기는 ack-eliciting 패킷 두 개를 받거나, 첫 번째 미확인 ack-eliciting 패킷 이후 10 ms가 지나면 ACK를 보낸다. 손실·재정렬 징후, CE 관찰, PMTU probe 수신 시에는 즉시 ACK를 보낸다. 중복 패킷은 새 ACK를 유발하지 않는다. `ack_delay_us`는 실제 지연을 넘겨서는 안 되며 10,000을 넘길 수 없다.

ACK receiver는 경로·수신 방향별로 DTLS 인증을 통과하고 새 Packet Number로 수락한 각 Obelisk Packet의 ECN codepoint를 누적해 `ect0_count`, `ect1_count`, `ce_count`에 넣는다. 새 path와 연관 시작의 세 counter는 모두 0이다. 모든 송신 Obelisk Packet은 ECT(0)으로 보냈다는 local ledger를 남겨야 한다.

송신자는 각 경로와 송신 방향마다 마지막으로 검증한 `ecn_largest_acked`, `[ect0, ect1, ce]` baseline, 그 시점까지 보낸 ECT(0) Packet Number를 유지한다. ACK의 `largest_acked`가 이전 `ecn_largest_acked`보다 **엄격히 클 때만** RFC 9000 §13.4.2의 ECN validation을 다음 치환으로 적용한다. (1) 세 counter는 baseline보다 감소할 수 없고, `ect1` 증가는 허용되지 않는다. (2) ACK range에서 이전 `ecn_largest_acked`보다 큰 새 ECT(0) Packet Number의 수를 `N`이라 할 때 `Δect0 + Δce >= N`이어야 한다. (3) 누적 `ect0 + ect1 + ce`는 해당 path에서 local ledger에 남긴 전체 ECT(0) 송신 Packet 수를 넘을 수 없다. (4) 검증 성공 시에만 baseline과 `ecn_largest_acked`를 갱신한다. 같은 값 또는 더 작은 값의 ACK는 UDP 재정렬 때문에 counter가 작아도 ECN 검증에서 완전히 무시한다. 어느 검증도 실패하면 그 경로를 `ECN_UNAVAILABLE`로 실패 처리한다. 이 참조는 validation 알고리즘만 가져오며 QUIC wire를 사용한다는 뜻은 아니다.

### 8.2 제어와 credit

`MAX_DATA(value=u64)`, `MAX_STREAM_DATA(stream_id:OVINT || maximum:u64)`, `MAX_STREAMS_BIDI(maximum:OVINT)`, `MAX_STREAMS_UNI(maximum:OVINT)`는 이전 값보다 큰 값만 새 credit으로 광고할 수 있다. 현재 수용한 maximum 이하인 well-formed 값은 재정렬·재전송과 구별할 수 없으므로 반드시 조용히 무시해야 하며, 그 값만으로 `PROTOCOL_VIOLATION`을 보내서는 안 된다.

초기 프로파일 한도는 다음과 같다.

| 항목                           | 기본값 |
| ------------------------------ | -----: |
| 초기 연결 신뢰성 데이터 window |  1 MiB |
| 초기 stream별 window           | 64 KiB |
| 연결 총 stream buffer          | 16 MiB |
| stream별 buffer                |  2 MiB |
| peer가 열 수 있는 bidi stream  |    128 |
| peer가 열 수 있는 uni stream   |    128 |
| endpoint reliable send queue   |  8 MiB |

`MAX_DATA`와 `MAX_STREAM_DATA`는 lifetime 누적 한도다. 수신자는 애플리케이션이 신뢰성 데이터를 소비하거나 abort/reset으로 메모리를 해제할 때 각 absolute maximum을 단조 증가시킬 수 있다. 16 MiB와 2 MiB는 lifetime 누적 credit 상한이 아니라 각각 연결과 stream에서 아직 소비·해제되지 않은 신뢰성 데이터의 최대 window다. 따라서 장시간 연관은 소비에 맞춰 `MAX_*`를 계속 전진시킬 수 있다. credit의 단위는 압축 전 애플리케이션 논리 byte이며 DTLS·frame·padding overhead는 포함하지 않는다.

각 방향의 `connection_accounted_total`은 0에서 시작하며, 수락한 모든 stream의 `accounted_end` 증가분과 새 RMSG ID의 전체 `total_length`를 합한 lifetime 누적값이다. 송신자는 새 stream byte의 최고 offset 증가분, 새 RMSG ID의 전체 `total_length`, RESET_STREAM의 아직 회계되지 않은 final size 증가분을 각각 한 번만 연결 `MAX_DATA`에 회계한다. stream byte는 동시에 해당 `MAX_STREAM_DATA`에도 회계한다. 재전송·중복 frame·padding·ACK·DATAGRAM은 credit을 다시 소비하지 않는다. 수신자는 peer가 광고한 absolute maximum을 넘는 새 논리 byte 또는 stream ordinal을 보내면 `FLOW_CONTROL_ERROR`로 닫아야 한다.

`DATA_BLOCKED`, `STREAM_DATA_BLOCKED`, `STREAMS_BLOCKED_*`는 해당 한도값을 담는 진단 신호일 뿐 credit을 늘리지 않는다. `GOAWAY`는 peer가 새 stream/RMSG를 시작하지 못하게 하는 단일 drain 선언이다. 세 cutoff는 모두 GOAWAY를 **받는** peer의 sender ID 공간을 뜻한다. peer는 `next_bidi_ordinal`/`next_uni_ordinal` 이상 ordinal의 stream이나 `next_rmsg_id` 이상의 RMSG를 새로 시작해서는 안 되며, 수신자는 그 값 이상인 새 stream/RMSG를 `PROTOCOL_VIOLATION`으로 거부한다. cutoff보다 작은 이미 시작된 신뢰성 데이터만 `max(3 × PTO, 30초)`의 drain 시간 안에 마칠 수 있다. byte-identical GOAWAY만 재전송할 수 있고, 다른 GOAWAY는 `PROTOCOL_VIOLATION`이다. 그 시간이 지나면 송신자는 `NO_ERROR` 또는 적절한 오류로 닫는다.

`CONNECTION_CLOSE` value는 `error_code:u16be || trigger_class:u8`다. `trigger_class`는 `0=unspecified`, `1=wire`, `2=identity`, `3=policy`, `4=resource`, `5=path` 중 하나다. 사람 읽는 문자열, endpoint 이름, credential, IP 주소를 넣어서는 안 된다.

### 8.3 SETTINGS와 나머지 제어 frame 문법

SETTINGS value는 정확히 한 개의 Deterministic CBOR map이다. duplicate key, 미지의 key, 누락 key, 잘못된 타입은 `FRAME_ENCODING_ERROR`다.

| key | 값                            | 필수 값 또는 범위     |
| --: | ----------------------------- | --------------------- |
|   0 | wire version text             | `"Obelisk/1-draft.0"` |
|   1 | profile flags uint            | 아래 bit 집합         |
|   2 | initial max data uint         | 1,048,576             |
|   3 | initial max stream data uint  | 65,536                |
|   4 | initial max streams bidi uint | 128                   |
|   5 | initial max streams uni uint  | 128                   |
|   6 | max packet frames uint        | 64                    |
|   7 | RMSG max length uint          | 1,048,576             |
|   8 | max incomplete RMSG uint      | 16                    |
|   9 | connection stream buffer uint | 16,777,216            |
|  10 | per-stream buffer uint        | 2,097,152             |
|  11 | max DATAGRAM topics uint      | 1,024                 |

profile flags는 `0x01=DIRECT_S2S`, `0x02=RELAY_PRIVACY`, `0x04=NATIVE_AUTH_REQUIRED`, `0x08=RELAY_CONTROL`이다. 일반 Direct S2S는 `0x01`만, Relay Privacy의 일반 native client↔service는 `0x02|0x04`만 사용한다. C↔R1과 C↔R2 Setup은 `0x08`, R1↔R2와 R2↔S admission delivery는 `0x01|0x08`만 사용한다. `0x08` 연관은 STREAM·RMSG·DATAGRAM·AUTH를 보내면 안 되며 11.2.1의 Relay Control Transfer와 DATA_BIND만 처리한다. Core는 Application Profile의 별도 설정이나 credential 의미를 SETTINGS에 넣지 않는다.

다음 frame value는 정확히 아래 문법을 따른다.

```text
GOAWAY                 = next_bidi_ordinal:OVINT || next_uni_ordinal:OVINT || next_rmsg_id:OVINT || code:u16be
MAX_DATA               = maximum:u64be
MAX_STREAM_DATA        = stream_id:OVINT || maximum:u64be
MAX_STREAMS_BIDI       = maximum:OVINT
MAX_STREAMS_UNI        = maximum:OVINT
DATA_BLOCKED           = limit:u64be
STREAM_DATA_BLOCKED    = stream_id:OVINT || limit:u64be
STREAMS_BLOCKED_BIDI   = limit:OVINT
STREAMS_BLOCKED_UNI    = limit:OVINT
AUTH                   = auth_nonce:32 || proof:48 || opaque_credential:bytes
AUTH_RESULT            = decision:u8 || app_code:u16be
ASSOCIATION_CONFIRM    = connection_instance_id:16
IDENTITY_CONFIRM       = Deterministic-CBOR(["OBIC/1", ctx, signature])
```

`GOAWAY` 뒤 peer는 표시된 next ordinal 이상인 새 stream이나 `next_rmsg_id` 이상인 새 RMSG를 시작할 수 없다. `AUTH`의 `proof`는 6.3의 HMAC-SHA-384 결과이고 `opaque_credential`은 1~512 byte여야 한다. `decision`은 `0=accepted`, `1=rejected`만 허용한다. `IDENTITY_CONFIRM`은 4.3의 정확한 `ctx`와 64 byte Ed25519 signature를 담아야 하고 value는 512 byte 이하여야 하며, profile이 요구하는 방향에서만 한 논리 값을 보낼 수 있다. AUTH가 필요한 profile에서 duplicate AUTH는 기존 결과를 재처리하거나 부작용을 만들지 않으며, 처음 결과를 그대로 재전송하거나 닫는다. Direct S2S dialer는 DTLS 시작 전에 새 `connection_instance_id`를 만들고 자신의 정확히 하나인 `ASSOCIATION_CONFIRM`에 넣는다. 수락자는 dialer의 유효한 확인을 받은 뒤에만 정확히 하나의 `ASSOCIATION_CONFIRM`을 보내며 그 16 byte 값을 그대로 echo해야 한다. 수락자가 독자적으로 만든 값, 누락, 불일치는 `PROTOCOL_VIOLATION`이다. 두 종단은 dialer가 만든 동일한 값으로만 6.4의 중복 해소를 수행하고, 확인 전에는 애플리케이션 데이터를 노출할 수 없다.

AUTH 수신자는 처음 유효 AUTH의 exact bytes와 `AUTH_RESULT`를 association 수명 동안 cache한다. byte-identical duplicate AUTH에는 같은 `AUTH_RESULT`만 새 Packet Number로 재전송하고, 다른 AUTH는 재검증·부작용 없이 `PROTOCOL_VIOLATION`으로 닫는다. AUTH sender는 첫 `AUTH_RESULT` exact bytes를 cache하며 byte-identical duplicate만 수락하고 다른 결과는 닫는다. Direct S2S의 `ASSOCIATION_CONFIRM`도 dialer가 만든 정확히 같은 16 byte의 duplicate만 idempotent하게 수락한다. 이 규칙들은 6.1의 pre-ACTIVE loss recovery 중에도 상태 전이를 두 번 만들지 않게 한다.

### 8.4 Stream

Stream ID는 다음 수식으로 계산한 OVINT다.

```text
stream_id = (ordinal << 2) | (direction << 1) | opener

direction = 0  양방향
direction = 1  단방향
opener    = 0  Dialer
opener    = 1  Acceptor
```

따라서 `0`은 Dialer bidi, `1`은 Acceptor bidi, `2`는 Dialer uni, `3`은 Acceptor uni다. ordinal은 0부터 증가하고 ID는 절대 재사용하지 않는다. 최대 ordinal은 `2^60 - 1`이며, 다음 ordinal이 이를 넘게 되면 새 stream을 열지 말고 `GOAWAY`와 새 연관으로 전환해야 한다. 첫 `STREAM` 또는 `RESET_STREAM`이 해당 stream을 연다. 높은 ordinal을 받았다고 낮은 모든 stream 객체를 만들면 안 되며, 그 ordinal은 해당 방향·종류의 `ordinal + 1`개 stream credit을 소비한다. 이미 그 credit을 소비한 뒤 더 낮은 ID가 와도 credit을 다시 소비하지 않으며, 실제 frame을 받을 때만 객체를 만든다. 수신자는 처음 128개 ordinal을 허용하고, peer가 연 stream이 terminal state가 되어 resource를 해제할 때 `MAX_STREAMS_*`를 올려 동시에 열린 stream을 최대 128개로 유지할 수 있다. `ordinal + 1`이 peer가 광고한 해당 종류의 `MAX_STREAMS_*`를 넘으면 `FLOW_CONTROL_ERROR`다.

아직 존재하지 않는 stream에 처음 도착하는 `STREAM` 또는 `RESET_STREAM`은 opener bit가 그 frame의 송신자를 가리켜야 한다. 이미 존재하는 bidi stream에서는 어느 쪽도 자기 송신 방향의 `STREAM`/`RESET_STREAM`을 보낼 수 있다. uni stream에서는 opener만 `STREAM`/`RESET_STREAM`을 보낼 수 있고, 반대편은 `STOP_SENDING`만 보낼 수 있다. 이 규칙, stream direction, 또는 terminal state와 맞지 않는 frame은 `STREAM_STATE_ERROR`다.

```text
STREAM value = stream_id:OVINT || offset:u64be || flags:u8 || data:bytes
flags bit 0 = FIN; 나머지 bit는 0

RESET_STREAM value = stream_id:OVINT || final_size:u64be || app_error:u16be
STOP_SENDING value = stream_id:OVINT || app_error:u16be
```

같은 `(stream_id, offset)` 범위에 서로 다른 byte를 넣거나, FIN/RESET의 final size가 서로 다르거나, final size 뒤에 data가 오면 `STREAM_STATE_ERROR`다. 겹치는 byte는 완전히 동일한 경우에만 허용한다. 첫 terminal event가 FIN이면 뒤늦은 RESET, 또는 첫 terminal event가 RESET이면 뒤늦은 FIN은 final size가 같아도 `STREAM_STATE_ERROR`다. FIN은 `offset + data.length`인 정확한 final offset을 고정한다.

각 stream 수신기는 `accounted_end`를 0에서 시작해, 수락한 data 범위의 끝 또는 선언된 final size 중 가장 큰 값으로만 단조 증가시킨다. 첫 STREAM 범위, FIN, RESET_STREAM을 수락하기 **전에** 그 event가 요구하는 새 `accounted_end`와 `delta = new_accounted_end - accounted_end`를 계산한다. `final_size`가 이미 받은 data 끝보다 작으면 `STREAM_STATE_ERROR`이고, `new_accounted_end > current_max_stream_data` **또는** `connection_accounted_total + delta > current_max_data`이면 data가 비어 있어도 `FLOW_CONTROL_ERROR`다. 이 두 absolute-limit 비교가 단순 delta 비교를 대체한다. 수락한 `delta`는 stream end와 연결 누적값에 정확히 한 번만 회계한다. 따라서 FIN이 만든 hole과 RESET_STREAM의 final size도 credit을 소비하지만 재전송·중복·이미 회계된 범위는 다시 소비하지 않는다. `RESET_STREAM`은 자기 송신 절반을 끝내며, `STOP_SENDING`을 받은 종단은 자기 송신 절반을 가능한 한 빨리 `RESET_STREAM`으로 끝낸다. 양방향 작업 취소는 자신의 `RESET_STREAM`과 상대에게 보내는 `STOP_SENDING`을 모두 사용한다. reset 전에 이미 애플리케이션에 노출한 byte는 되돌리지 않는다.

### 8.5 RMSG: 신뢰성·비순서 원자 메시지

RMSG ID는 송신 방향별로 0부터 빈틈없이 증가하는 OVINT이고 재사용하지 않는다. sender의 `sender_outcome_watermark`는 첫 ID 전에는 개념적으로 `-1`이며, sender는 terminal outcome을 받은 ID들의 1,024 bit out-of-order bitmap을 유지해 연속 outcome이 이어지는 만큼만 이 watermark를 전진시킨다. sender는 `sender_outcome_watermark + 1,024`보다 큰 ID를 새로 시작해서는 안 된다. 따라서 outcome이 순서를 바꿔 도착해도 sender와 receiver의 허용 window가 어긋나지 않는다. receiver의 local `delivery_watermark`도 첫 ID 전에는 개념적으로 `-1`이며, receiver는 `delivery_watermark + 1`부터 `delivery_watermark + 1,024`까지만 새 RMSG ID를 admission한다. receiver는 정확히 1,024 bit의 bounded out-of-order bitmap과 그 window의 조립/terminal state만 만들며, 이 window 밖의 미래 새 ID는 allocation 전에 `RMSG_LIMIT_ERROR`로 닫고 watermark 이하의 은퇴 ID는 애플리케이션에 다시 노출하지 않고 조용히 버린다.

```text
RMSG value = rmsg_id:OVINT || flags:u8 || offset:u64be ||
             total_length:u64be || fragment:bytes
flags bit 0 = FIRST; 나머지 bit는 0

RMSG_RECEIPT value = rmsg_id:OVINT
RMSG_ABORT value   = rmsg_id:OVINT || app_error:u16be
```

- 송신자가 처음 보내는 조각은 반드시 `FIRST=1`, `offset=0`이어야 한다. 모든 조각은 같은 `total_length`를 반복해 넣어야 하며, `FIRST=1`은 `offset=0`에서만 허용한다.
- 수신자는 재정렬 때문에 non-FIRST 조각을 먼저 받아도 해당 `total_length`로 한도를 검사·예약한 뒤 저장할 수 있다. 같은 RMSG ID에서 total length가 다르거나 범위가 total length를 넘으면 `RMSG_LIMIT_ERROR`다. 겹치는 fragment byte는 완전히 같을 때만 허용하며, 다른 byte가 하나라도 겹치면 `RMSG_LIMIT_ERROR`다. 정확히 같은 범위·byte의 duplicate는 idempotent하다.
- `total_length`는 1 MiB 이하, 조각 수는 메시지당 2,048 이하, 동시에 조립 중인 메시지는 16개 이하, 총 조립 메모리는 8 MiB 이하, 조립 수명은 60초 이하다.
- 송신자는 첫 조각을 보내기 전 전체 `total_length`만큼 연결 신뢰성 credit을 예약한다. 재전송은 credit을 다시 소비하지 않는다.
- 수신자는 모든 byte를 검증하고 전체 `total_length`만큼 메모리를 예약한 뒤에만 조각을 저장한다. 애플리케이션 전달 대기열에 원자적으로 넣은 뒤에만 `RMSG_RECEIPT`를 보낸다. 이 영수증은 DB 저장, UI 표시, 외부 API 호출, 영구적 부작용의 영수증이 아니다.
- 메모리·시간·프로토콜 제약 때문에 원자 전달을 보장할 수 없으면 `RMSG_ABORT`를 보내고 해당 ID를 폐기한다.

receiver가 `RMSG_RECEIPT` 또는 `RMSG_ABORT`를 만들면 그 ID는 즉시 terminal이며, contiguous terminal ID가 이어지는 만큼 `delivery_watermark`와 1,024 bit admission window를 즉시 전진시킨다. 이 전진은 outcome을 담은 packet의 ACK와 독립적이다. receiver는 최대 1,024개의 별도 `terminal_outcome_ledger`에 `(rmsg_id, exact outcome frame, outcome packet ACK state)`를 보관하고, `RMSG_RECEIPT`와 `RMSG_ABORT`를 그 packet이 ACK될 때까지 신뢰성 control로 재전송한다. ACK되지 않은 outcome의 같은 RMSG duplicate에는 저장한 같은 outcome만 재전송하며, ACK된 outcome 또는 `delivery_watermark` 이하의 더 오래된 duplicate는 애플리케이션에 다시 노출하지 않고 조용히 버린다.

`terminal_outcome_ledger`가 가득 찼을 때 receiver는 새 RMSG를 abort하거나 연관을 닫아서는 안 된다. 완성된 메시지는 `delivery_pending`으로 보류하고, delivery pending 또는 deferred abort marker는 조립 중인 메시지와 함께 16개·8 MiB·60초 한도에 포함한다. ledger slot이 ACK로 비면 receiver는 가장 작은 pending ID부터 정확히 한 번 queue에 넣거나 abort하고 새 terminal outcome을 만든다. pending 상태를 더 보관할 수 없는 valid RMSG fragment는 조용히 버릴 수 있지만 terminal 또는 delivered로 만들 수 없으며, malformed input과 달리 `RMSG_LIMIT_ERROR`를 보내서는 안 된다.

RMSG sender는 모든 원본 byte와 조립 metadata를 terminal outcome을 받을 때까지 보존해야 한다. 각 unretired RMSG에는 독립적인 `outcome_pto_count=0`을 둔다. RMSG를 처음 보내거나 outcome PTO probe를 보낸 뒤 `PTO × 2^outcome_pto_count` 동안 terminal outcome이 없으면 sender는 모든 fragment를 새 Packet Number와 새 DTLS record로 다시 보낸 뒤 count를 하나 증가시킨다. 기존 fragment의 직렬화 길이가 현재 `B - 8`에 맞으면 같은 fragment를 쓴다. 9.4에 따라 `P`가 낮아져 맞지 않으면 같은 RMSG ID·total length·각 offset의 정확한 원본 byte를 보존한 더 작은 non-overlap fragment로 재분할하고, `FIRST=1`은 offset 0에만 둔다. 재분할 뒤에도 메시지당 2,048 fragment 한도와 모든 RMSG 문법·credit 규칙을 만족해야 하며, 이는 새 RMSG나 새 credit 소비가 아니다. 이 probe는 congestion window와 pacer를 지키며, packet ACK만으로 중단·reset하지 않는다. outcome PTO가 여섯 번 연속 만료되면 sender는 `CONNECTION_TIMEOUT`으로 연관을 닫는다. 따라서 receiver가 packet을 ACK했더라도 일시적인 delivery/ledger 포화로 terminal outcome을 만들지 못한 RMSG는 나중에 안전하게 다시 제시될 수 있다.

송신자가 자신의 RMSG ID에 대한 `RMSG_RECEIPT` 또는 `RMSG_ABORT`를 받으면 그 RMSG를 terminal로 만들고 fragment 재전송과 outcome PTO를 중단한다. sender는 수신 여부를 나타내는 1,024 bit outcome bitmap과, set bit마다 outcome 종류 및 abort이면 `app_error`를 담는 별도의 1,024-entry bounded outcome table을 보관하고 contiguous outcome만 `sender_outcome_watermark`로 은퇴한다. 아직 outcome window 안인 같은 ID에 대해 table의 기존 값과 상충하는 terminal outcome이 오면 `PROTOCOL_VIOLATION`이다. 이미 sender outcome watermark 이하인 terminal frame은 조용히 무시하며, 미래 ID 또는 한 번도 보낸 적 없는 ID의 terminal frame은 `PROTOCOL_VIOLATION`이다.

RMSG는 하나의 살아 있는 연관 안에서만 “대기열 삽입까지 한 번” 전달한다. 연결이 끊긴 뒤 송신자는 결과를 알 수 없으며, 재접속 후 중복 방지·업무 idempotency는 Application Profile이 맡는다. 다음 RMSG ID가 `2^62 - 1`을 넘게 되면 새 RMSG를 시작하지 말고 `GOAWAY`와 새 연관으로 전환해야 한다.

### 8.6 최신 값 우선 DATAGRAM

```text
DATAGRAM value = topic_id:OVINT || generation:u64be || data:bytes
```

`topic_id`는 송신 방향·연관 범위의 불투명 ID이고, 연관 전체에서 재사용하지 않는다. 한 방향에서 연관 수명 동안 만들 수 있는 topic은 최대 1,024개다. 수신자는 이 한도를 넘는 새 topic을 조용히 버리며, 이미 은퇴한 topic을 다시 살리지 않는다. `generation`은 topic별로 엄격히 증가해야 하며 wrap 직전에는 topic을 영구 은퇴하고 새 topic ID를 사용해야 한다. 송신자는 같은 topic의 아직 전송하지 않은 더 오래된 값을 새 값으로 교체해야 한다. 수신자는 이미 본 더 큰 generation보다 작거나 같은 값을 조용히 버린다.

DATAGRAM은 재전송, receipt, 순서 보장, 신뢰성 flow credit을 갖지 않는다. 다만 혼잡 제어와 relay quota에는 완전히 종속된다. DATAGRAM은 조각화할 수 없으며 Packet Number까지 포함한 직렬화 길이가 현재 `B`에 들어가지 않으면 local `DATAGRAM_TOO_LARGE` 실패로 처리하고 wire에 보내지 않는다. 수신 애플리케이션이 즉시 받지 못하면 연결은 별도 DATAGRAM queue를 만들지 않고 해당 값 또는 더 오래된 값을 버릴 수 있다. 의미상 만료 시간과 상태 병합 규칙은 애플리케이션이 정한다.

## 9. 전송 복구, 혼잡 제어, MTU

### 9.1 손실 복구

송신자는 ack-eliciting Packet Number와 그 안의 재전송 가능한 논리 frame을 추적한다. ACK된 packet의 frame은 완료 처리한다. `bytes_in_flight`는 아직 ACK되지 않은 **ack-eliciting packet만**의 UDP header 뒤 실제 UDP payload byte(DTLS와 Obelisk overhead 포함)를 합산한다. ACK와 PADDING만 든 packet은 peer가 다시 ACK할 의무가 없으므로 congestion window admission과 `bytes_in_flight`에서 제외한다. 다만 이 packet도 pacer와 rate cap은 반드시 따른다. 손실 판단은 다음 중 하나다.

- packet threshold: 같은 방향에서 더 큰 3개 packet이 ACK됨
- time threshold: `9/8 × max(latest_rtt, smoothed_rtt)`가 지남

ack-eliciting packet의 실제 UDP payload는 유효 ACK가 확인하거나 위 기준으로 loss가 선언될 때 정확히 한 번 `bytes_in_flight`에서 뺀다. ACK와 loss가 모두 뒤늦게 관찰되어도 두 번 빼서는 안 되며, loss로 선언된 packet은 ACK되지 않았다는 이유만으로 window를 계속 점유해서는 안 된다. 9.4의 probe-only loss를 제외한 loss 선언은 9.2의 CUBIC congestion event를 일으킨다. 같은 recovery epoch의 추가 loss는 cwnd를 다시 낮추지 않으며, recovery epoch는 그 감소 뒤 보낸 packet을 새 ACK가 확인할 때 끝난다.

RTT 표본 전에는 `latest_rtt=1초`, `smoothed_rtt=1초`, `rttvar=500ms`, `min_rtt=undefined`, `granularity=1ms`, PTO count `0`으로 초기화한다. 첫 유효 RTT 표본에서는 `latest_rtt=smoothed_rtt=min_rtt=sample`, `rttvar=sample/2`로 설정한다. 이후의 RTT·rttvar 갱신은 RFC 9002 §5.3의 식을 그대로 사용하되, `min_rtt`에서는 ack delay를 빼지 않고 smoothed RTT에서는 최대 10ms로 clamp한 실제 ack delay만 감산한다. PTO는 `smoothed_rtt + max(4 × rttvar, granularity) + max_ack_delay`로 계산하며 `max_ack_delay=10ms`를 사용하고 매 PTO마다 2의 거듭제곱 backoff를 곱한다. 이 참조는 추정식만 가져오며 QUIC wire를 사용한다는 뜻은 아니다. PTO 만료 시 정확히 두 개의 ack-eliciting probe를 보낸다. 일반 application data는 congestion window를 우회할 수 없지만, PTO에 한해 현재 `P`의 합계 `2 × P`까지만 cwnd를 초과하는 recovery allowance를 허용한다. probe도 pacer를 따라야 하고 `bytes_in_flight`에 회계한다. PTO 횟수는 새 ack-eliciting packet의 ACK를 받은 경우에만 0으로 reset한다. 6회 연속 PTO 뒤에는 `CONNECTION_TIMEOUT`으로 닫는다.

재전송은 이전 DTLS ciphertext를 그대로 다시 보내는 것이 아니라, 아직 필요한 논리 frame을 새 Obelisk Packet Number와 새 DTLS record로 보낸다. ACK, PADDING, 이미 취소된 frame, DATAGRAM은 재전송하지 않는다.

### 9.2 혼잡 제어와 스케줄링

모든 ack-eliciting packet은 하나의 congestion window와 pacer를 공유한다. ACK와 PADDING만 든 packet은 congestion window를 소비하지 않지만 같은 pacer·rate cap을 공유한다. 기본 혼잡 제어는 RFC 9438 CUBIC과 RFC 9406 HyStart++다. 구현체는 CUBIC의 `C=0.4`, `β=0.7`, fast convergence, recovery epoch, minimum/initial congestion window를 RFC 9438에 맞게 적용하고, HyStart++는 slow start에서만 적용해야 한다. 검증된 ACK에서 `ce_count`가 증가하면 그 path의 첫 CE 증가를 CUBIC congestion event로 처리해 loss와 같은 `β` 감소와 recovery epoch 시작을 수행한다. 같은 recovery epoch에서 추가 CE 증가는 cwnd를 다시 낮추지 않으며, recovery epoch는 그 감소 뒤 보낸 packet을 새 ACK가 확인할 때 끝난다. CE는 packet loss나 재전송을 직접 선언하지 않는다. BBR 계열은 로컬 실험 기능으로만 허용되며 wire 협상·호환성 주장·기본값이 될 수 없다.

송신 우선순위는 다음 순서를 따른다.

1. 손실 복구, CONNECTION_CLOSE, GOAWAY, SETTINGS, ACK 등 제어 frame
2. 짧은 interactive RMSG와 요청/응답 stream byte
3. realtime DATAGRAM
4. bulk stream byte

제어는 높은 우선순위를 갖지만 rate cap과 pacer를 우회할 수 없다. 같은 등급 안에서는 weighted fair scheduling을 사용하고, 지속적 고우선 traffic이 낮은 등급을 영구 기아 상태로 만들면 안 된다. 정확한 weight는 구현 로컬 정책이지만 모든 구현은 congestion window·pacing·ECN 규칙을 우회해서는 안 된다.

### 9.3 ECN

ECT(0) 사용과 경로별 검증은 필수다. 새로 원본 UDP datagram을 만드는 종단은 ECT(0)을 요청해야 하며, relay forwarding leg는 받은 ECT/CE를 단조롭게 보존한다. 따라서 받은 CE는 출력도 CE여야 하며 relay가 이를 ECT(0)으로 덮어써서는 안 된다. DTLS handshake/RRC는 이후 control이 성립할 때까지 ECN counter validation에서 제외할 수 있다. SETUP_BIND/DATA_BIND raw AEAD record도 pre-association tuple 검증만을 위한 고정 크기 traffic이므로 Not-ECT로 보낼 수 있으며, 그 뒤 실제 C↔S data path의 Obelisk ACK로 ECN을 검증해야 한다. Obelisk Packet은 8.1의 ACK counter로, RCT fragment traffic은 11.2.1의 RCT_ACK counter로 반드시 검증한다. OS가 UDP ECN 송수신 정보를 제공하지 않거나, 해당 ACK counter가 ECN을 검증하지 못하거나, Relay Privacy 경로에서 R1/R2가 ECT/CE를 보존하지 않으면 해당 경로를 활성화해서는 안 된다.

### 9.4 DPLPMTUD와 padding

초기 안전 UDP payload 최대치 `P`는 1,200 byte다. 이는 UDP header 뒤의 payload이며 DTLS record와 Obelisk bytes를 모두 포함한다. 구현체는 IP fragmentation을 유발하지 않도록 DF/동등한 OS 기능을 사용해야 한다. 1,200 byte를 전송할 수 없는 경로는 `PATH_MTU_ERROR`로 실패한다.

RFC 8899 DPLPMTUD를 사용하여 검증된 값만 MTU를 올릴 수 있다. probe는 고유 `probe_id:u64`를 가진 로컬 추적 항목이며, PING을 담은 ack-eliciting packet을 정확한 목표 크기까지 PADDING으로 채워 보낸다. ACK가 해당 Packet Number를 확인할 때만 성공으로 간주한다. probe는 congestion window와 pacer에는 포함되지만, probe만의 손실은 CUBIC congestion loss로 해석해서는 안 된다. ICMP Packet Too Big는 quoted packet의 source/destination IP·IP protocol·UDP port·최근 보낸 DTLS record가 현재 path의 추적 항목과 정확히 맞고, 보고 IP MTU가 있는 경우에만 감소 힌트로 쓴다. 이때 `P_hint = reported_IP_MTU - actual_outbound_IP_header_length(including extensions) - 8(UDP header)`이며, `P_hint`는 현재 `P`를 낮출 수만 있고 올릴 수 없다. quoted packet을 안전하게 상관시킬 수 없거나 환산값이 1,200보다 작으면 각각 무시 또는 `PATH_MTU_ERROR`다. local send error도 같은 방향의 안전한 감소 근거일 때만 사용한다. ICMP만으로 MTU를 올릴 수 없으며, 더 낮은 안전 크기를 확인하면 즉시 낮추고 probe 상태를 초기화한다. 어떤 사유로든 `P`가 낮아지면 현재 `B - 8`에 맞지 않는 outstanding reliable logical frame은 재전송 전에 안전하게 재직렬화·재분할해야 하며, RMSG는 8.5의 재분할 규칙을 따른다.

ICMP나 local send error가 없더라도 PMTU black hole을 반드시 회복해야 한다. 방향별로 `black_hole_count`를 0에서 시작한다. `P > 1,200`일 때 실제 UDP payload가 1,200 byte보다 큰 ack-eliciting application 또는 재전송 가능한 logical frame packet이 9.1의 packet 또는 time threshold로 손실 처리되면, sender는 그 실제 길이를 `candidate_payload_len`으로 둔 black-hole candidate를 만든다. DPLPMTUD probe만 든 packet의 손실은 이 candidate를 만들지 않는다. 그 candidate의 다음 PTO에서 9.1이 요구하는 두 probe 중 하나는 정확히 1,200 byte UDP payload가 되도록 PADDING한 PING(`base probe`)이어야 한다. base probe는 별도 congestion 예외를 만들지 않고 기존 PTO recovery allowance·cwnd·pacer를 그대로 따른다. candidate가 시작된 뒤 UDP payload 길이가 `candidate_payload_len` 이상인 ack-eliciting packet 하나라도 ACK되면 candidate와 `black_hole_count`를 즉시 0으로 reset한다. 반대로 그런 ACK 없이 base probe가 인증된 ACK로 확인되면 count를 하나 늘리고 그 candidate를 끝낸다. 이후 새 candidate와 같은 base-probe 확인이 한 번 더 연속으로 일어나 count가 2가 되면, 송신자는 즉시 `P=1,200`으로 낮추고 candidate·count·상승 probe state를 모두 초기화해야 한다. 이는 CUBIC의 이미 발생한 loss 처리를 되돌리거나 추가 congestion event를 만들지 않는다. MTU 재상승은 다시 검증된 DPLPMTUD probe로만 가능하다.

각 새 association path와 10.2에서 promote된 새 path는 방향별 `base_1200_verified=false`로 시작한다. `SETTINGS_EXCHANGE` 이후 PING이 허용되는 즉시 sender는 정확히 1,200 byte UDP payload가 되도록 PADDING한 PING을 보내고, 그 Packet Number의 ACK를 받기 전에는 그 방향의 새 application-sourced frame을 보내서는 안 된다. 이 ACK를 받으면 `base_1200_verified=true`다. `P=1,200`에서 아직 확인되지 않은 이 baseline PING, 또는 실제 UDP payload가 256 byte보다 큰 reliable/application packet이 loss로 선언되면 그 실제 길이를 `minimum_mtu_candidate_len`으로 둔다. 그 다음 PTO의 두 probe 중 하나는 정확히 256 byte UDP payload가 되도록 PADDING한 PING(`small probe`)이어야 한다. `minimum_mtu_candidate_len` 이상 packet의 ACK는 candidate와 `minimum_mtu_failure_count`를 0으로 reset한다. 반대로 그런 ACK 없이 small probe가 인증된 ACK로 확인되면 count를 하나 늘리고 candidate를 끝낸다. 이 대비가 두 번 연속 일어나 count가 2가 되면 path는 이 명세의 최소 1,200 byte를 지원하지 않는 것이므로 `PATH_MTU_ERROR`로 닫아야 한다. small probe도 확인되지 않으면 이 규칙으로 MTU를 추정하지 않고 9.1의 일반 PTO/timeout 처리를 따른다.

애플리케이션 데이터가 들어가는 UDP datagram은 현재 검증된 `P`를 사용하여 가능한 경우 다음 bucket 중 원래 record 길이 이상인 가장 작은 값까지 PADDING한다.

```text
256, 512, 768, 1024, P
```

`P`는 현재 안전 UDP payload 최대치이며 처음에는 1,200이다. 현재 `B - 8`보다 큰 직렬화 frame은 패킷에 들어갈 수 없으며, 신뢰성 데이터는 더 작은 조각으로 나눠야 한다. 송신자는 7.1.1의 `O`와 `B`를 계산해 Obelisk `PADDING`을 넣고 최종 UDP payload가 정확히 bucket 크기가 되도록 조정한다. padding frame으로 정확한 길이를 만들 수 없는 경우(예: 필요한 추가 byte가 1인 경우)에만 바로 아래 길이를 그대로 보낼 수 있다. handshake·ACK·경로 제어만 있는 traffic은 이 padding 의무 대상이 아니다. 의도적인 coalescing 지연이나 dummy packet은 금지한다.

## 10. 직접 경로 이동

### 10.1 CID 정책

Direct S2S와 명시적으로 직접 연결된 Core 연관(선택적으로 C↔R1/R1↔R2 control 포함)이 이동 가능하려면 DTLS CID (RFC 9146)와 Enhanced Return Routability Check, RRC (RFC 9853)를 모두 지원해야 한다. 양방향 initial active CID는 각각 비어 있지 않은 96비트 무작위 값이어야 하며, 개인정보·endpoint ID·백엔드 라우팅 의미를 담아서는 안 된다. 이 연관의 `NewConnectionId`가 운반하는 `cid_immediate`와 `cid_spare`도 모두 정확히 12 byte CSPRNG 값이어야 한다. 한 peer가 상대에게 제공한 active·spare·grace CID 집합 안에는 같은 값이나 다른 CID의 prefix가 될 수 있는 값이 있어서는 안 된다. 모든 값이 정확히 12 byte이므로 이 규칙은 중복 CID와 record demultiplexing의 길이 모호성을 함께 금지한다. 각 endpoint는 하나의 local UDP socket과 그것을 공유하는 DTLS demultiplexing scope 안에서 자신이 수신할 모든 live association의 active·spare·grace CID를 association 경계를 넘어 유일하게 관리해야 한다. 새 initial CID 또는 `NewConnectionId` CID가 같은 scope의 아직 폐기되지 않은 다른 association CID와 같으면, 그 CID를 수신할 endpoint는 이를 허용해서는 안 되며 해당 association을 DTLS fatal `illegal_parameter` alert로 끝내야 한다. grace/quiet period가 끝난 뒤에만 그 CID를 재사용할 수 있다.

각 방향에서 peer가 제공한 CID pool은 active 정확히 1개, spare 최대 2개, grace 최대 2개, 합계 최대 5개다. `usage=cid_immediate`인 `NewConnectionId`의 `cids` vector에는 정확히 하나의 CID만, `usage=cid_spare`의 vector에는 현재 비어 있는 spare slot을 채우는 1개 또는 2개의 CID만 들어갈 수 있다. `RequestConnectionId.num_cids`는 정확히 부족한 spare slot 수인 1 또는 2만 허용한다. `cid_immediate` 회전으로 grace CID가 세 개가 될 상황이면 sender는 그 회전을 미뤄야 하며 receiver도 수락해서는 안 된다. 이 상한을 넘는 `NewConnectionId` vector·pool·grace 전이는 allocation 전에 `illegal_parameter` alert로 끝내고, 2보다 큰 `num_cids` 또는 아직 채워지지 않은 request가 있는 추가 request는 `too_many_cids_requested` alert로 끝낸다.

handshake 직후에는 각 방향에 active CID 하나만 있어도 된다. ACTIVE 전 또는 최초 이동 시도 전에는 각 peer가 `cid_spare` `NewConnectionId`로 두 개의 예비 CID를 제공하고 상대의 DTLS ACK를 받아야 한다. 예비 CID 하나를 새 path에 쓰면 즉시 보충을 요청하며, 두 개가 다시 준비되기 전에는 두 번째 동시 이동을 시작하거나 수락해서는 안 된다. DTLS record replay protection은 활성화가 필수이며 Obelisk Packet Number의 중복 제거를 대체하지 않는다.

이동 가능성은 handshake에서 명시적으로 협상한다. dialer(DTLS client)는 ClientHello에 `connection_id` extension(type 54, 자신이 받을 정확히 12 byte CID)과 빈 `rrc` extension(type 61)을 **둘 다** 넣어야 한다. acceptor(DTLS server)는 ServerHello에 자신이 받을 정확히 12 byte `connection_id`와 빈 `rrc` extension을 **둘 다** 넣어야 한다. 양쪽 exchange가 모두 성공한 경우에만 `migratable`이다. 하나라도 없거나 CID가 비어 있거나 길이가 다르면 연관은 `non-migratable`로 고정하며, 그 연관에서 RRC, CID 기반 address update, `NewConnectionId`, `RequestConnectionId`를 사용해서는 안 된다. RRC record를 handshake 협상 전에 보내는 것은 `PROTOCOL_VIOLATION`이다.

CID는 검증된 직접 경로 이동, 장기 수명 회전, KeyUpdate 때 DTLS 1.3 `NewConnectionId`로 회전한다. 새 CID는 `cid_immediate` 또는 필요한 예비 CID 집합으로 제공한다. 새 `NewConnectionId`는 이전 `NewConnectionId`의 DTLS ACK 전에는 보내서는 안 된다. `RequestConnectionId`는 이전 request에 대응하는 `NewConnectionId`를 받아 request가 fulfilled되기 전에는 다시 보내서는 안 된다. 이전 CID는 새 CID update의 DTLS ACK 뒤 최소 `max(3 × PTO, 30초)` 동안만 grace mapping으로 받아들이고 그 뒤 폐기한다. CID와 UDP tuple은 그 quiet period가 끝나기 전에 재사용해서는 안 된다.

Relay-Control association(C↔R1, C↔R2 Setup, R1↔R2, R2↔S)은 `rct_bytes_in_flight`가 0이고, 미완성 RCT·`RCT_COMPLETE` retry·terminal tombstone·semantic result 대기·bootstrap current transmission unit이 전혀 없는 quiescent 상태에서만 CID/RRC 이동을 허용할 수 있다. 이 상태 하나라도 존재하면 그 control association은 이동 불가이며, source tuple 변화는 새 control association과 새 admission 절차를 요구한다. 따라서 RCT/raw bootstrap의 local ledger를 주소 이동 사이에 복사하거나 old-path ACK에 결합할 필요가 없다.

Relay Privacy의 C↔S 데이터 연관은 CID를 사용해서는 안 된다. 두 릴레이가 관찰 가능한 장기 공통 식별자를 만들지 않기 위해 고정 데이터 tuple에서만 동작하며, NAT/주소 변화는 새 회선과 새 C↔S DTLS 연관으로 처리한다.

### 10.2 RRC 절차

직접 연관에서 source tuple이 달라졌을 때 종단은 RFC 9853 Enhanced Return Routability Check를 사용한다. CID로 식별된 인증된 record가 새 tuple에서 와도 즉시 peer address를 바꾸지 않는다. Basic RRC의 유효한 `path_response`가 끝나기 전에는 모든 새 candidate tuple에서 application data, Obelisk Packet, 새 DTLS application data를 수락하거나 RRC 이외의 record를 보내서는 안 된다. primary path로 promote되기 전 candidate tuple에 보내는 **모든** UDP payload(RRC, PING, 재전송 logical frame 포함)의 누계는 그 tuple에서 받은 유효한 authenticated DTLS/RRC byte의 3배를 넘을 수 없다. 예산이 없으면 해당 frame을 보류해야 한다. 먼저 새 난수 cookie가 든 `path_challenge`를 이전 tuple에 보낸다. 이전 tuple의 `path_response`가 오면 기존 경로를 유지한다. 이전 tuple에서 `path_drop`이 오거나, 이전 tuple이 `T = 3 × old_rtt` 안에 응답하지 않거나 old RTT를 모르면 1초가 지나면, 새 tuple에서 Basic RRC를 수행하고 새 tuple의 `path_response`를 받은 뒤에만 이동한다. RRC는 DTLS content type 27의 `path_challenge=0`, `path_response=1`, `path_drop=2`이며 Obelisk frame이나 Obelisk ACK/loss 대상이 아니다.

자신의 UDP source tuple을 바꿔 Basic RRC를 시작하는 종단과, 새 local path에서 유효한 **Basic** `path_challenge`를 받아 `path_response`를 보내는 종단은 각각 격리된 outbound path candidate를 만든다. 이 candidate의 CUBIC, RTT, PTO, ECN 송신 ledger/baseline, PMTU는 `P=1,200`에서 새로 시작하며 Packet Number 공간은 다시 시작하지 않는다. `path_response`를 보낸 responder candidate는 primary path가 되기 전에도 위 3배 amplification 예산과 새 path의 cwnd/pacer·`P=1,200` 예산 아래 outstanding reliable logical frame을 새 Packet Number로 재전송하고 ack-eliciting PING을 보낼 수 있다. 단, 새로운 application-sourced data를 보내거나 들어온 application data를 application에 전달해서는 안 된다. validator는 유효한 Basic `path_response`로 commit한 직후 새 tuple에 authenticated ack-eliciting PING 하나를 반드시 보낸다. responder candidate는 그 PING 또는 그 뒤의 authenticated peer record를 같은 새 path에서 받으면 primary path로 promote한다. 이전 tuple에서 온 Enhanced RRC challenge에 대한 response는 이런 candidate를 만들거나 state를 reset해서는 안 된다. 이 규칙은 한쪽이 새 path ECN counter를 0부터 시작할 때 반대쪽이 이전 path baseline을 계속 보내는 것과 단방향 reliable traffic의 migration deadlock을 함께 막는다.

새 source tuple로 이동이 검증되면 IP 주소·주소 패밀리·port 변화 여부와 무관하게 CUBIC 상태, RTT 추정, PTO backoff, ECN 검증, PMTU 추정(`P=1,200`)을 초기화한다. commit 순간 이전 tuple로 보낸 아직 ACK되지 않은 ack-eliciting packet instance는 `bytes_in_flight`에서 정확히 한 번 retire하되 새 path의 congestion loss로 처리해서는 안 된다. 그 packet 안의 아직 완료되지 않은 재전송 가능한 논리 frame은 새 Packet Number, 새 path의 cwnd/pacer와 `P=1,200` 예산 아래에서 다시 queue한다. 이전 tuple의 late authenticated ACK는 해당 old packet ledger와 이미 재queue한 논리 frame의 완료 상태만 정리할 수 있고, 새 path의 CUBIC·RTT·PTO backoff·ECN baseline/`ecn_largest_acked`·PMTU를 갱신하거나 되돌려서는 안 된다. Packet Number의 방향별 중복 제거 window와 번호 공간은 이동 전후에 계속 유지한다. ECN ACK counter baseline은 검증된 새 tuple에서 온 첫 authenticated ACK로 새로 잡고 그 뒤에는 8.1의 `ecn_largest_acked` 규칙만 적용한다. 단순 source IP/port 변경만으로 새 경로를 신뢰해서는 안 된다. CID 또는 Enhanced RRC를 지원하지 않는 구현체는 non-migratable이며 주소 변경 뒤 재접속해야 한다.

## 11. Relay Privacy 프로파일

### 11.1 비공모 가정과 데이터 노출

Relay Privacy는 R1과 R2가 서로 다른 운영·법적·관찰 도메인에 있고 공모하지 않는다는 가정에 의존한다. 같은 운영사만이 아니라 같은 로그/SIEM, hosting account, key-management tenant, 운영 접근권한, 공통 분석 계정을 공유하면 같은 privacy domain으로 간주한다. 같은 domain의 R1/R2 조합은 선택해서는 안 된다.

| 관찰자 | 알 수 있는 것                              | 알 수 없어야 하는 것                      |
| ------ | ------------------------------------------ | ----------------------------------------- |
| R1     | C의 IP/포트, 선택된 R2, 자신의 quota       | S의 endpoint/IP, C↔S 평문, ExitGrant 내용 |
| R2     | R1, S의 서명된 endpoint 후보, 자신의 quota | C의 IP/포트, IngressGrant 내용, C↔S 평문  |
| S      | R2의 source tuple, C↔S 인증·앱 data        | C의 IP/포트, R1                           |

이 프로파일은 packet 크기 bucket만 제공하며 dummy traffic이나 일정한 전송률을 만들지 않는다. 따라서 양쪽 릴레이와 전역 관찰자는 시간·볼륨 상관 정보를 볼 수 있다.

디렉터리 조회는 별도의 metadata 누출점이다. C는 R1을 통해 대상별 discovery를 수행해서는 안 되며, R1에 `opaque-path`, S Descriptor, S 후보를 전달해서는 안 된다. 클라이언트는 서명된 realm snapshot을 직접 받아 로컬에서 target을 고른다.

R1의 R2 선택 후보군과 선택 알고리즘은 realm, 자신의 `relay_privacy_domain_id`와 다른 서명된 R2 `relay_privacy_domain_id`, 용량, 무작위성에만 의존해야 하며 S, `opaque-path`, S Descriptor hash, 서비스 종류에 의존해서는 안 된다. 대상별 egress pool이나 대상별 R2 고정 배정은 금지한다. C도 11.3의 OPEN_OK에서 받은 R2 Descriptor가 현재 Directory·Status·Revocation에서 유효하고 R1의 privacy domain과 다른지 독립적으로 확인해야 한다.

### 11.2 세 개의 제어 평면

```text
1. C  ↔ R1 : Relay-Control DTLS (직접)
2. R1 ↔ R2 : Relay Peer-Control DTLS (상호 인증 직접)
3. C  ↔ R2 : Setup-DTLS (R1이 바이트 그대로 전달)
```

각 평면은 별도 UDP tuple과 별도 state를 가진다. setup slot과 data slot은 서로 다른 UDP 포트·tuple이고 재사용할 수 없다. R1은 3번의 암호문을 해독하지 않으며, R2는 C의 source tuple을 얻어서는 안 된다. R1은 C의 원본 source tuple을 R2에 전달하는 header, Proxy Protocol, 진단 field, 로그 field를 삽입해서는 안 된다.

세 제어 평면과 C↔S data handshake는 모두 4장의 DTLS 1.3 암호 프로파일을 사용한다. C↔R1과 C↔R2 Setup은 각 relay의 Descriptor pin을 검증하고, R1↔R2는 상호 ML-DSA-87 client authentication을 사용한다. C↔R2 Setup에서 grant/PoP 이외의 C stable identity를 요구해서는 안 된다. 이 제어 연결에서 relay는 자신의 제어 대상에 대한 정보를 볼 수 있지만, C↔S application plaintext의 종단이 되는 것은 아니다.

R1↔R2 control은 상호 인증된 Relay Peer-Control이고, R2가 S 후보로 데이터그램을 보내기 전에 Exact ExitGrant 및 서명된 Descriptor를 검사하게 한다. 따라서 R2가 임의 UDP proxy가 되는 것을 막는다.

### 11.2.1 Relay Control Transfer

11절의 `ADMISSION_OPEN`, reservation, RAE, permit, grant 관련 relay 제어 메시지는 Relay Control Profile의 DTLS application-data bootstrap record다. 이는 일반 Obelisk Packet이나 애플리케이션 data가 아니며, C↔R1 Relay-Control, C↔R2 Setup, R1↔R2 Peer-Control, R2↔S admission delivery에서 해당 peer IdentityConfirm·SETTINGS와 필요한 경우 ASSOCIATION_CONFIRM이 끝난 뒤에만 허용된다. DATA_BIND만은 11.5의 별도 record이고, C↔R2 record는 R1이 내용 해석 없이 그대로 전달한다.

UDP 재정렬 때문에 위 prerequisite가 아직 끝나지 않은 association에서 DTLS 인증을 통과한 relay bootstrap record가 먼저 도착할 수 있다. relay는 방향별 최대 8개·합계 8 KiB의 exact raw record만 `relay_precondition_cache`에 보관하고, 아직 RAE 복호화·grant 검증·reservation·port·application side effect를 만들지 않는다. 같은 byte는 deduplicate하고, cache 한도를 넘는 record는 조용히 폐기한다. prerequisite가 끝나면 cached record를 도착 순서대로 이 절의 정상 state machine에 넣는다. sender의 RCT/작은-record 재전송은 ACK·응답을 받지 못한 cache overflow를 회복해야 하며, prerequisite 미충족만으로 close나 상세 오류를 보내서는 안 된다.

모든 `r1_boot_epoch`와 `r2_boot_epoch` wire 값은 정확히 16 byte CBOR byte string이다. relay는 시작할 때 새 local epoch를 만들고, 자신의 epoch를 담는 입력은 현재 값과 정확히 같을 때만 처리한다. authenticated R1↔R2 Peer-Control에서 처음 수락한 peer epoch는 그 association의 RAM state에 고정하며, 이후 모든 response·reservation·grant·PoP binding의 peer epoch가 정확히 같아야 한다. relay 재시작·peer epoch 변경·Peer-Control 재수립은 기존 grant, admission, reservation, slot, circuit을 모두 무효화하며, 이전 epoch를 다시 수락하거나 새 state로 승격해서는 안 된다.

RAE, AdmissionPermit capsule, IngressGrant, ExitGrant처럼 1,200 byte UDP payload에 들어가지 않을 수 있는 객체는 단일 DTLS record나 IP fragmentation으로 보내서는 안 된다. 이들은 다음의 제한된 Relay Control Transfer(RCT)로만 보낸다.

```text
RCT_FRAGMENT = Deterministic-CBOR([
  "ORCTF/1", object_type:u8, transfer_id:16, object_sha384:48,
  total_length:u32, offset:u32, fragment:bytes
])
RCT_ACK      = Deterministic-CBOR([
  "ORCTK/1", transfer_id:16, received_ranges[], ack_sequence:uint,
  ect0_count:uint, ect1_count:uint, ce_count:uint
])
RCT_COMPLETE = Deterministic-CBOR(["ORCTC/1", transfer_id:16, object_sha384:48])
RCT_COMPLETE_ACK = Deterministic-CBOR(["ORCTD/1", transfer_id:16, object_sha384:48])
RCT_ABORT    = Deterministic-CBOR(["ORCTA/1", transfer_id:16, generic_code:u8])
```

위 문법의 `received_ranges[]`는 Deterministic-CBOR array이며, 각 원소는 정확히 두 개의 canonical CBOR unsigned integer인 `[start_offset:u32, end_offset:u32]` array다. 각 원소는 `0 ≤ start_offset < end_offset ≤ total_length`여야 하며, 최대 64개를 내림차순으로 담는다.

그 밖의 relay 제어 message는 하나의 Deterministic CBOR array로 된 768 byte 이하의 bootstrap record여야 하며, 하나의 UDP datagram에는 그 record 하나만 들어간다. 여러 제어 message를 하나의 record 또는 datagram에 coalesce해서는 안 된다.

모든 `RCT_FRAGMENT`, `RCT_ACK`, `RCT_COMPLETE`, `RCT_COMPLETE_ACK`, `RCT_ABORT`는 정확히 하나의 DTLS application-data record이자 하나의 UDP datagram이어야 하며 coalesce할 수 없다. `ack_sequence`와 세 ECN counter는 canonical CBOR unsigned integer이고, 수신 방향별로 0에서 시작한다. `ack_sequence`가 `2^64 - 1` 뒤 증가해야 하면 control association을 닫고 새 association을 만들어야 한다.

작은 relay control record는 generic application data가 아니라 idempotent control object다. 그 state key는 ADMISSION_OPEN의 `open_ref`, PermitContext/ExitContext의 `[admission_ref, control association]`, reservation의 `admission_ref` 또는 `reservation_ref`, grant의 grant ID, DATA_SLOT의 `[admission_ref, circuit_nonce]`처럼 각 절에 지정한 값이다. sender는 응답 또는 다음 단계의 유효 record를 받기 전 같은 raw record를 1초, 2초 간격으로 최대 세 번(최초 포함) 보낼 수 있다. receiver는 같은 key와 byte-identical record에 저장한 같은 response 또는 다음 record만 재전송하고, 같은 key의 다른 bytes에는 새 state를 만들지 않고 조용히 거부한다. retry도 local rate cap과 pacing을 우회해서는 안 되며, 세 번째 뒤에도 진행하지 못하면 일반 control 실패로 끝낸다.

R1이 만든 admission context를 C의 두 제어 association에 결합할 때는 `PermitContext = Deterministic-CBOR(["Obelisk PermitContext v1", admission_ref:16])`를 사용한다. C는 `ADMISSION_OPEN_OK`에서 받은 `admission_ref`를 C↔R1과 C↔R2 Setup에 각각 하나의 논리 record로 보내며, 위 retry 규칙의 byte-identical duplicate만 허용한다. 각 relay는 그 association·slot이 현재 유효한 같은 admission-only reservation에 속할 때만 수락한다. R2는 C↔R2 Setup에서 유효한 PermitContext를 처음 받으면 작은 `ExitContext = Deterministic-CBOR(["Obelisk ExitContext v1", exit_context_token:32, expires])`를 돌려준다. EntryPermit/ExitPermit RCT와 그 뒤 grant는 이 local context에만 결합되며, 만료·중복·다른 association의 context는 조용히 거부한다.

`entry_context_token`과 `exit_context_token`은 각각 32 byte CSPRNG 값이고 admission ref·현재 control association·slot expiry에만 결합된다. 각각의 원래 relay(R1 또는 R2)와 C만 그 token을 현재 association/slot에 결합하거나 수락할 권한을 가진다. S/role 7/PermitIssuer는 encrypted RAE·ServiceApproval·permit 발급 과정에서 이를 불투명한 binding 값으로 일시 처리할 수 있으나, relay identity에 결합하거나 다른 용도로 해석해서는 안 된다. 두 token은 서로 유도하거나 재사용할 수 없고, 반대 relay, R1↔R2 control, data plane, telemetry, log, debug export에 넣어서는 안 된다. S/Authority와 issuer는 `expires + 30초` 뒤 raw token 또는 이를 포함한 capsule/permit cache를 폐기해야 하며, 그 전에도 암호화된 duplicate-result cache 외의 영속 저장을 해서는 안 된다.

`object_type`은 `0=raw RAE`, `1=raw AdmissionPermitCapsule`, `2=raw EntryPermit`, `3=raw ExitPermit`, `4=raw IngressGrant`, `5=raw ExitGrant`, `6=raw GrantProof`다. sender는 association·송신 방향에서 30초 동안 재사용하지 않은 16 byte CSPRNG `transfer_id`를 골라야 하며, receiver의 transfer state key는 `(association, 수신 방향, transfer_id)`다. `fragment`는 1~768 byte이고, 마지막 조각을 제외한 `offset`은 768의 배수여야 한다. 모든 fragment는 동일한 type, transfer ID, object hash, total length를 반복한다. 같은 transfer ID의 type/hash/length가 처음 수락한 값과 다르거나 `offset + fragment.length`가 total length를 넘으면 해당 transfer를 `RCT_ABORT`하고 resource state를 폐기한다. 이미 받은 `[offset, offset + fragment.length)`와 겹치는 모든 absolute byte도 완전히 같아야 하며, 하나라도 다르면 같은 조치를 취한다. 정확히 같은 byte를 재전달하거나 부분 overlap의 모든 공통 byte가 같은 경우는 idempotent하다. `total_length`는 type 0의 raw RAE에서 32 KiB 이하, 그 밖의 type에서 64 KiB 이하다. 완성 객체의 raw byte SHA-384는 `object_sha384`와 같아야 한다. fragment 문법·hash·한도 오류에는 사람 읽는 오류를 돌려주지 않는다.

receiver는 새 RCT transfer를 조립 buffer에 넣기 전에 terminal tombstone quota도 함께 예약해야 한다. association·수신 방향별로 미완성 transfer는 하나, terminal tombstone은 최대 16개와 16 KiB metadata만 허용하며, process 전체 tombstone은 최대 4,096개와 2 MiB metadata만 허용한다. tombstone은 `(association, direction, transfer_id, object_type, object_sha384, total_length, exact terminal RCT_COMPLETE 또는 RCT_ABORT)`만 담고 raw object byte를 보관해서는 안 된다. 먼저 tombstone을 조회한다. 같은 `transfer_id`의 type·hash·total length가 모두 일치하면 fragment를 다시 조립하거나 새 state를 만들지 않고 저장한 terminal record만 재전송한다. 하나라도 다르면 transfer-ID conflict이므로 tombstone을 바꾸거나 조립·route·semantic·forward state를 만들지 말고 조용히 폐기한다. 새 transfer에 필요한 incomplete slot 또는 tombstone reservation이 없으면 receiver는 buffer·route·semantic state를 만들거나 forward하지 않고 `RCT_ABORT(resource)`를 보내거나 공격성 입력이면 조용히 폐기한다. 완성 또는 이 quota를 예약한 transfer의 abort 뒤 raw assembly는 즉시 폐기하되 tombstone은 30초 동안 반드시 유지하며, capacity 압박 때문에 이 TTL 안에 evict해서는 안 된다.

type 0의 완성 객체는 11.3의 `RAE` Deterministic-CBOR byte sequence **그 자체**다. `[target_descriptor_hash, directory_generation, request_id, RAE]` 같은 별도 RCT wrapper는 존재하지 않으며, `total_length`와 `object_sha384`는 각각 이 raw RAE의 byte length와 `SHA-384(raw_RAE)`다. type 1도 11.3.1의 raw AdmissionPermit capsule 그 자체이고, type 2~5는 해당 이름의 raw COSE_Sign byte sequence, type 6은 11.3.3의 raw `GrantProof` Deterministic-CBOR byte sequence다. 어떤 type도 RCT 밖의 중첩 transfer wrapper를 hash·length에 포함해서는 안 된다.

R2는 type 0을 재조립하고 hash를 확인한 **뒤에만** canonical raw RAE outer를 parse한다. `realm_id`, target Descriptor hash, directory generation, request ID, expiry, recipient kid를 현재 signed Directory·Descriptor와 비교한다. 이어서 `rae_route_key = Deterministic-CBOR([realm_id, target_descriptor_hash, directory_generation, request_id, expires])`를 만들고, process-wide pending map에 `rae_route_key → (C↔R2 Setup association, SHA-384(raw_RAE), deadline)`로 원자적으로 예약한다. 각 C↔R2 Setup association은 동시에 정확히 하나의 live `rae_route_key`만, R2 process 전체는 최대 4,096개와 2 MiB metadata만 보관할 수 있다. `deadline`은 RAE expiry와 이 Setup association의 admission slot expiry 중 이른 시각이다. map quota가 없으면 R2는 새 state나 admission delivery를 만들지 않고 `RCT_ABORT(resource)`로 끝내며, live map은 deadline 전 capacity 압박 때문에 evict해서는 안 된다. 같은 association에서 같은 raw hash로 들어온 duplicate만 기존 map entry로 수렴할 수 있다. 같은 key에 다른 raw hash 또는 다른 C↔R2 Setup association이 결합되려 하면 R2는 `RCT_ABORT(resource)`로 그 transfer를 끝내고 admission delivery를 해서는 안 된다. 첫 예약만 새 local transfer ID로 같은 raw RAE bytes를 R2↔S admission delivery에 보낼 수 있다. R2는 type 1을 hash 확인 뒤 capsule outer의 `[realm_id, target_descriptor_hash, directory_generation, request_id, rae_expires]`로 같은 `rae_route_key`를 재구성하고, 아직 살아 있으며 유일한 map entry를 찾아야만 그 entry의 정확한 C↔R2 Setup association으로 새 local transfer ID를 써서 raw capsule bytes를 전달할 수 있다. map이 없거나 만료·모호·불일치하면 R2는 capsule을 조용히 폐기하거나 일반 admission 실패만 내며 다른 C association으로 전달해서는 안 된다. R2는 capsule body를 열거나 변경해서는 안 된다. 이 규칙으로 RCT의 type 0 hash, ServiceApproval의 `rae_sha384`, RAE replay key는 모두 같은 `SHA-384(raw_RAE)`를 뜻한다.

`received_ranges[]`는 half-open `[start_offset, end_offset)` 쌍의 내림차순 배열이고 최대 64개다. 각 range는 받은 완전 fragment들의 byte 범위만 나타내며 overlap·인접 range·미래 offset은 허용하지 않는다. 수신자는 새 fragment 두 개를 받거나 첫 미확인 fragment 뒤 10ms가 지났을 때 RCT_ACK를 보내며, gap/중복/마지막 fragment에서는 즉시 보낸다. 새 RCT_ACK마다 그 방향의 `ack_sequence`를 증가시키며 재전송은 정확히 같은 sequence·counter를 써야 한다. RCT_ACK는 Obelisk `ACK`가 아니다.

RCT receiver는 association·수신 방향별로 DTLS 인증을 통과한 각 RCT_FRAGMENT datagram의 ECN codepoint를 세 counter에 누적한다. RCT sender는 마지막 검증 `ack_sequence`, `[ect0, ect1, ce]` baseline, 전체 ECT(0) fragment 송신 수를 유지한다. `ack_sequence`가 이전 값보다 엄격히 클 때만 ECN을 검증한다. counter 감소, `ect1` 증가, 새로 처음 확인된 fragment datagram 수 `N`보다 작은 `Δect0 + Δce`, 또는 전체 counter 합이 local ECT(0) fragment 송신 수를 넘는 경우는 `ECN_UNAVAILABLE`로 control path를 실패시킨다. 성공 때만 baseline을 갱신하고 `ce_count` 증가에는 9.2의 CUBIC congestion event 규칙을 적용한다. 같은 또는 더 작은 `ack_sequence`의 counter는 재정렬 때문에 완전히 무시한다.

수신자는 association과 방향별로 하나의 미완성 RCT만, 총 64 KiB만, 30초 이하로 보관한다. 앞서 예약한 terminal tombstone은 30초간 duplicate fragment에 재할당 없이 같은 terminal record를 보낼 수 있게 한다. 조립 receiver는 `RCT_COMPLETE`을 보낸 뒤 `complete_pto_count=0`으로 두고, 같은 `RCT_COMPLETE`을 `PTO × 2^complete_pto_count` 뒤 재전송하며 매번 count를 증가시킨다. 유효한 `RCT_COMPLETE_ACK`가 transfer ID와 object hash에 정확히 맞으면 이 retry를 멈춘다. 세 번의 COMPLETE 전송에도 ACK가 없으면 해당 transfer를 일반 control 실패로 끝낸다. object sender는 유효한 `RCT_COMPLETE`을 받으면 즉시 같은 `RCT_COMPLETE_ACK`를 보내며, duplicate COMPLETE에도 같은 ACK를 재전송한다. `RCT_COMPLETE`는 조립·hash 검증까지의 전송 완료일 뿐 application admission 또는 grant 수락을 뜻하지 않는다. `RCT_ABORT`의 `generic_code`는 `0=invalid`, `1=resource`, `2=expired`만 사용하며, 공격성 입력에는 응답 없이 폐기할 수 있다.

RCT sender는 새 object의 fragment를 offset 오름차순으로 보내야 한다. 각 fragment에는 wire에 나타나지 않는 local transmission ledger `(offset, length, sent_at, record_bytes, transmission_count, retransmitted, in_flight)`를 두며, 재전송 전에 이전 current record instance를 loss로 retire하므로 fragment마다 동시에 in-flight인 instance는 하나뿐이다. `record_bytes`는 실제 DTLS record가 차지한 UDP payload byte다. RCT와 같은 outbound Relay-Control association의 768 byte 이하 bootstrap record는 같은 directional CUBIC/cwnd/pacer와 `rct_bytes_in_flight`를 공유한다. bootstrap record도 state key마다 current transmission unit 하나만 둘 수 있으며, 그 절이 정한 저장된 response 또는 다음 유효 record가 semantic ACK다. semantic ACK는 unit을 `rct_bytes_in_flight`에서 정확히 한 번 retire하고 CUBIC ACK event로 처리하되 RTT 표본은 만들지 않는다. 1초·2초 retry 시 이전 unit을 loss로 retire하고 9.1의 CUBIC recovery 규칙을 적용한 새 unit을 만들며, 세 번째 뒤에는 새 unit을 만들지 않는다. terminal response는 세 번째 전송 또는 state expiry 때 반드시 loss로 retire해야 한다.

각 association/direction의 RCT congestion state는 `rct_bytes_in_flight`, initial `10 × 1,200` byte congestion window, 1초 initial RTT, 9.1·9.2의 CUBIC/pacer를 사용한다. 단, RCT_ACK에는 ack delay가 없으므로 RCT RTT 표본의 ack delay는 항상 0이다. receiver의 `ack_sequence`가 이전에 검증한 값보다 엄격히 크고 `received_ranges[]`가 처음으로 fragment 전체 `[offset, offset + length)`를 포함할 때만 그 fragment를 확인한다. 이때 current in-flight record instance의 `record_bytes`를 `rct_bytes_in_flight`에서 정확히 한 번 retire하고, fragment를 완료 처리한다. 해당 fragment가 재전송된 적이 없을 때만 `now - sent_at`을 RTT 표본으로 사용한다(Karn 규칙). 이미 loss로 retire한 이전 instance, duplicate RCT_ACK, partial range, 같은 또는 더 작은 `ack_sequence`는 `rct_bytes_in_flight`·RTT·PTO를 바꾸지 않는다.

아직 확인되지 않은 current RCT fragment는 (a) 더 높은 offset의 fragment 세 개가 처음 확인되었거나 (b) `sent_at` 뒤 `9/8 × max(latest_rtt, smoothed_rtt)`가 지나면 loss다. loss가 되면 `record_bytes`를 `rct_bytes_in_flight`에서 정확히 한 번 retire하고 9.1의 loss/CUBIC recovery 규칙을 적용한다. 새 fragment confirmation이 하나라도 오면 RCT PTO count를 0으로 reset한다. 그렇지 않으면 9.1의 PTO 식(ack delay 0)을 쓰며, PTO마다 아직 필요한 fragment 중 최대 두 개를 새 DTLS record sequence로 보낸다. 각 fragment의 전송은 최초를 포함해 최대 세 번이고, PTO probe도 cwnd·pacer와 `rct_bytes_in_flight` 회계를 따른다. 세 번째 전송도 확인되지 않았거나 30초 안에 `RCT_COMPLETE`가 없으면 해당 setup/control 작업을 일반 실패로 끝내며 새 grant·회선·service admission을 만들지 않는다. RCT는 Obelisk Packet Number·ACK·RMSG를 사용하지 않으므로 AUTH 전 대형 object를 암묵적으로 RMSG에 실어 보내는 것은 금지한다.

전송 완료와 semantic 결과는 별개다. type 0 RAE, type 2 EntryPermit, type 3 ExitPermit, type 6 GrantProof의 sender는 유효한 `RCT_COMPLETE`을 확인한 뒤에도 각각 type 1 capsule, type 4/5 grant와 GrantChallenge, GrantResult처럼 이 문서가 정한 다음 semantic 결과를 기다린다. 그 결과가 오지 않으면 sender는 현재 PTO, 그 뒤 두 배 PTO 간격으로 같은 raw object를 새 local `transfer_id`로 다시 RCT 전송할 수 있으며, 최초 전송을 포함해 최대 세 transfer만 시도한다. 이 retry는 해당 RAE/permit/grant nonce의 type-specific expiry를 넘을 수 없다. receiver는 `(association, object_type, SHA-384(raw_object), 해당 절의 idempotency state key)`로 이미 처리한 request를 알아보고 새 grant·permit·port·검증 부작용을 만들지 않은 채 저장한 정확한 semantic 결과만 재전송해야 한다. 세 transfer 뒤에도 결과가 없으면 sender는 type-specific expiry까지 결과를 기다릴 수 있으나 새 state나 추가 transfer를 만들지 않으며, expiry 뒤에는 일반 control 실패로 끝낸다.

### 11.3 사전 연관 Relay Admission과 Split Grant

C↔S DTLS exporter에 결합한 6.3의 `AUTH`는 data circuit과 C↔S handshake가 생긴 뒤에야 가능하다. 따라서 data circuit을 열기 전에 grant를 받는 절차는 `AUTH`를 앞당겨 사용해서는 안 된다. 대신 Relay Privacy는 **사전 연관 RelayAdmissionEnvelope(RAE)**를 사용하고, C↔S가 열린 뒤에는 6.3의 `AUTH`를 다시 필수로 검증한다.

RAE의 application credential 의미와 Admission Authority의 권한 판단은 Application Profile의 몫이지만, Relay Privacy Profile의 RAE **봉투 암호 형식**은 이 절에서 고정한다. C는 target Descriptor의 현재 `admission_recipient`에서 `recipient_kid`와 ML-KEM-1024 public key를 얻는다. 그 key가 Descriptor의 유효 기간 밖이거나 Revocation되었으면 RAE를 만들 수 없다. C는 request마다 새 ML-KEM-1024 reply key pair를 만들고 다음 plaintext와 AAD를 Deterministic CBOR로 직렬화한다.

```text
rae_plaintext = [
  "Obelisk RelayAdmissionEnvelope plaintext v1", realm_id,
  target_descriptor_hash, directory_generation, request_id:16, expires, profile:u8,
  k_entry_hash, k_exit_hash, entry_context_token:32, exit_context_token:32,
  reply_mlkem1024_public,
  opaque_application_credential
]
rae_aad = [
  "Obelisk RelayAdmissionEnvelope aad v1", realm_id,
  target_descriptor_hash, directory_generation, request_id:16, expires,
  recipient_kid:16
]
```

`request_id`는 16 byte 난수, `expires`는 생성 시각보다 늦고 90초 이하여야 하며, `opaque_application_credential`은 16 KiB 이하, 완성된 RAE는 32 KiB 이하여야 한다. C는 `(ss, kem_ciphertext) = ML-KEM-1024.Encaps(recipient_public)`을 계산하고, `A = Deterministic-CBOR(rae_aad)`, `P = Deterministic-CBOR(rae_plaintext)`로 둔다.

```text
PRK   = HKDF-Extract(SHA-384, SHA-384(A), ss)
key   = HKDF-Expand(PRK, "Obelisk RAE key v1" || 0x00 || SHA-384(A), 32)
nonce = HKDF-Expand(PRK, "Obelisk RAE nonce v1" || 0x00 || SHA-384(A), 12)
body  = AES-256-GCM.Seal(key, nonce, P, A)
RAE   = Deterministic-CBOR([
  "ORAE/1", realm_id, target_descriptor_hash, directory_generation,
  request_id, expires, recipient_kid, kem_ciphertext, body
])
```

RAE outer의 realm·target Descriptor hash·directory generation·request ID·expiry·recipient kid는 `rae_aad`를 재구성하기 위해 필요한 최소 공개 routing context다. C는 RAE를 11.2.1의 RCT type 0 raw object로만 C↔R2 Setup에 보낸다. R2는 hash-verified raw outer에서 이 문맥을 읽어 admission delivery만 routing할 수 있지만, `profile`, `K_entry`/`K_exit` hash, 두 context token, reply key, credential은 body 밖으로 내보내지 않는다. S 또는 S가 위임한 Admission Authority만 outer context로 AAD를 재구성해 같은 Descriptor key로 decapsulation하고 AAD·plaintext의 모든 중복 field가 같은지 확인한다. `profile`은 정확히 `0x06`(`0x02|0x04`)이어야 한다. decapsulation, AEAD, CBOR, expiry, key/Descriptor 검증 오류는 같은 일반 admission 실패로 처리한다. RAE는 다른 Descriptor, recipient key, directory generation, request ID, profile, reply key, `K_entry`/`K_exit` hash, entry/exit context token으로 다시 결합할 수 없다. R1, R2, HTTPS gateway는 RAE를 열거나 success result·credential을 해석·발급·변경해서는 안 된다.

### 11.3.1 ServiceApproval

`opaque_application_credential`의 허용 여부는 Application Profile이 결정하지만, **성공 결정을 permit으로 바꾸는 권한·결합·재생 방지**는 Core다. RAE를 복호화하고 credential을 허용한 S 또는 Admission Authority는 현재 target Descriptor의 `admission_authority_keyset_id`와 정확히 같은 role 7 keyset으로만 다음 payload를 Ed25519와 ML-DSA-87 COSE_Sign 쌍으로 서명한다. protected `content type`은 정확히 `ob-service-approval/1`이다.

```text
ServiceApproval = {
  0:"ob-service-approval/1", 1:realm_id, 2:approval_id:16,
  3:target_descriptor_hash:48, 4:directory_generation,
  5:rae_sha384:48, 6:request_id:16, 7:reply_mlkem1024_public,
  8:k_entry_hash:48, 9:k_exit_hash:48,
  10:entry_context_token:32, 11:exit_context_token:32,
  12:profile:u8, 13:issued, 14:expires
}
```

`approval_id`는 Authority가 RAE마다 새로 만드는 16 byte CSPRNG 값이다. `rae_sha384`는 수신한 정확한 raw RAE Deterministic-CBOR bytes의 SHA-384이며, 나머지 field는 성공적으로 검증한 RAE plaintext/outer context에서 바이트 단위로 복사한다. credential 원문, 사용자 ID, C IP/tuple, R1/R2 ID·boot epoch, grant ID는 이 object에 절대로 넣지 않는다. `issued`와 `expires`는 현재 Descriptor, role 7 delegation, Status, RAE의 expiry를 넘을 수 없고 `expires`는 `issued` 뒤 90초 이하여야 한다.

EntryPermitIssuer와 ExitPermitIssuer는 bare client request·relay request·HTTPS gateway request 또는 application credential을 받아 permit을 만들지 않는다. 각 issuer는 ServiceApproval의 두 signature가 같은 현재 role 7 keyset에 속하는지, 그 delegation의 유일한 audience `[endpoint_id, descriptor_sha384]`가 현재 유효한 signed Descriptor의 endpoint ID와 정확한 `target_descriptor_hash`에 일치하는지, Descriptor의 `admission_authority_keyset_id`도 같은지 확인한다. 이어서 Directory generation, Descriptor/Status/Revocation, RAE hash·request ID·reply key·두 PoP hash·두 context token·`profile=0x06`·expiry를 모두 검증한다. 이 검증은 전달 채널의 발신 주소나 TLS identity만으로 대체할 수 없다. ServiceApproval 전달 채널은 별도 종단간 기밀성·무결성과 상호 인증을 가져야 하며, Obelisk를 쓸 경우 Direct S2S의 상호 client authentication을 사용한다.

각 issuer는 `[realm_id, approval_id]`와 `[realm_id, rae_sha384]` 둘 다에 대해 모든 활성 replica가 공유하는 원자적 `NEW → PENDING → ISSUED` 상태를 유지한다. 하나가 이미 다른 payload에 결합되었으면 일반 실패로 거부한다. `PENDING` duplicate는 새 검증·자원 할당·permit 서명을 만들지 않으며, `ISSUED`의 byte-identical duplicate만 이전에 저장한 같은 permit bytes를 반환할 수 있다. 이 상태와 결과는 `expires + 30초`까지 보존한다. issuer가 이 상태를 replica/재시작 경계에서 보장할 수 없으면 마지막 가능 expiry 뒤 90초 동안 새 ServiceApproval을 fail-closed로 거부해야 한다. 따라서 재생된 승인, 다른 reply key/PoP key/context로 바꾼 승인, 또는 서비스가 승인 ID만 바꿔 다시 보낸 같은 RAE는 새 permit을 얻을 수 없다.

S/Admission Authority는 서로 독립된 realm 공통 EntryPermitIssuer(role 5)와 ExitPermitIssuer(role 6)에 같은 검증된 ServiceApproval을 보낸다. 두 Authority는 R1/R2 도메인에 속할 수 없고, C IP·C source tuple·R1/R2 ID·boot epoch를 받거나 로그에 남겨서는 안 된다. 전자는 ServiceApproval의 Entry binding으로 EntryPermit을, 후자는 Exit binding으로 ExitPermit을 만든다. 두 Authority는 모든 Relay Privacy target에 공통인 각자의 keyset으로만 서명해야 하므로, R1은 signer로 S를 식별할 수 없고 한 issuer compromise만으로 양쪽 permit을 만들 수 없다. 이 S/Authority→issuer 요청은 application control plane이며 Direct S2S 또는 C↔S data path의 중간 hop이 아니다.

두 permit은 C reply public key에만 열리는 AdmissionPermit capsule로 돌아온다. 이 절의 `directory_generation`과 `rae_expires`는 검증한 raw RAE outer의 같은 값을 byte-for-byte 복사한 것이며, ServiceApproval 또는 permit 자체의 expiry와 바꾸거나 혼동해서는 안 된다. S/Authority는 `capsule_plaintext = Deterministic-CBOR(["Obelisk AdmissionPermitCapsule plaintext v1", realm_id, target_descriptor_hash, directory_generation, request_id, rae_expires, profile, k_entry_hash, k_exit_hash, entry_context_token, exit_context_token, entry_permit_cose_bytes, exit_permit_cose_bytes])`, `capsule_aad = Deterministic-CBOR(["Obelisk AdmissionPermitCapsule aad v1", realm_id, target_descriptor_hash, directory_generation, request_id, rae_expires])`를 만든다. `(ss_c, kem_ciphertext_c) = ML-KEM-1024.Encaps(reply_mlkem1024_public)`와 `PRK_c = HKDF-Extract(SHA-384, SHA-384(capsule_aad), ss_c)`에서 label을 각각 `"Obelisk AdmissionPermitCapsule key v1"`, `"Obelisk AdmissionPermitCapsule nonce v1"`로 한 HKDF-Expand 32/12 byte 결과를 사용해 AES-256-GCM을 봉인한다. capsule은 `Deterministic-CBOR(["ORPC/1", realm_id, target_descriptor_hash, directory_generation, request_id, rae_expires, kem_ciphertext_c, body_c])`다. C는 outer의 `[realm_id, target_descriptor_hash, directory_generation, request_id, rae_expires]`로 정확히 하나의 미결 reply private key를 고르고 같은 outer context로 AAD를 재구성한 뒤에만 이를 연다. C는 모든 plaintext bound field, profile, 두 context token, 두 permit signature를 다시 검증한다. R2는 capsule을 byte-for-byte 전달할 뿐 열거나 재암호화하지 않는다.

S/Admission Authority는 `SHA-384(Deterministic-CBOR(["Obelisk RAE replay v1", realm_id, target_descriptor_hash, directory_generation, request_id, SHA-384(raw_RAE_bytes)]))`를 replay key로 사용한다. 이 key의 상태는 expiry까지 원자적으로 `NEW → PENDING → ISSUED`가 된다. `ISSUED` duplicate에는 새 permit·grant를 발급하지 않고 이전과 byte-identical한 capsule만 다시 전달할 수 있으며, `PENDING` duplicate는 새 검증·자원 할당을 만들지 않는다. cache는 모든 활성 replica에서 공유되어야 한다. Authority 전체 재시작으로 이 cache를 보존할 수 없으면 90초 동안 새 RAE 처리를 거부한 뒤에만 다시 admission을 열어야 한다. 이 짧은 anti-replay 상태는 Core의 오프라인 저장 기능이 아니다.

사전 연관 흐름은 다음과 같다.

1. C는 R1을 거치지 않고 서명된 Directory에서 S Descriptor를 고른다.
2. C는 C↔R1 Relay-Control을 열고 R1의 relay-control IdentityConfirm만 검증한 뒤, 새 `open_ref:16`을 만들어 target을 담지 않은 `ADMISSION_OPEN = ["Obelisk AdmissionOpen v1", open_ref, realm_id, 0x06]`을 보낸다. R1은 대상과 무관하게 R2를 선택하고 새 `entry_context_token`을 만들며 R1↔R2의 admission-only reservation을 만든다. R1은 `ADMISSION_OPEN_OK = ["Obelisk AdmissionOpen OK v1", open_ref, admission_ref:16, entry_context_token:32, r1_setup_port, r2_endpoint_id, r2_descriptor_sha384:48, expires]`를 C에게 돌려준다. `expires`는 발급 뒤 90초를 넘을 수 없으며, 이 admission setup slot은 RCT admission만 허용하고 data port를 만들지 않는다. C는 받은 R2 ID/hash가 자신의 현재 서명된 Directory 안의 유효한 R2 Descriptor와 정확히 일치하고 R1과 다른 `relay_privacy_domain_id`인지 검증한다. C는 C↔R1 control association에서 PermitContext를 하나의 논리 record로 보낸 뒤, R1 candidate의 `r1_setup_port`에서 SETUP_BIND의 OK를 검증한다. 그 뒤에만 Setup-DTLS를 시작하며 C↔R2 Setup의 certificate SPKI와 IdentityConfirm `endpoint_id`/`endpoint_descriptor_sha384`가 OPEN_OK의 `r2_endpoint_id`/hash와 정확히 같을 때만 계속한다. R1은 그 뒤 record를 대응하는 `r2_setup_port`로 byte-for-byte 전달한다.
3. C는 C↔R2 Setup-DTLS가 성립하면 그 association에서 PermitContext를 하나의 논리 record로 보내고, R2가 돌려준 `exit_context_token`을 받는다. C는 그 뒤 두 context token과 `0x06` profile을 넣은 raw RAE를 admission setup slot의 C↔R2 Setup-DTLS에서 RCT type 0으로 보낸다. R1은 이 DTLS record를 byte-for-byte 전달하므로 target과 두 token을 알 수 없다.
4. R2는 exact signed Descriptor와 짧은 길이·rate limit을 확인한 뒤, **admission delivery만** 허용하는 상호 인증 R2↔S control로 RAE를 보낸다. R2는 이 단계에서 C↔S data slot을 열거나 일반 UDP를 전달해서는 안 된다.
5. S/Admission Authority가 RAE를 검증하면, realm 공통의 서로 독립된 EntryPermitIssuer/ExitPermitIssuer에게 split permit 발급을 요청하고 C에게만 열리는 AdmissionPermit capsule을 돌려준다. R2는 이를 해독하지 못한 채 C↔R2 Setup으로 전달한다.
6. C는 이미 각각 한 번 수락된 두 PermitContext를 가진 상태에서 ExitPermit을 **C↔R2 Setup-DTLS에서만** 제시한다. R2는 이를 검증해 ExitGrant를 로컬에서 발급하고 `K_exit` PoP를 확인한 뒤에만 `exit_ready_ref`를 R1에 보낸다. 그 후 C는 EntryPermit을 **C↔R1 Relay-Control에서만** 제시한다. R1은 이를 검증해 IngressGrant를 로컬에서 발급하고 `K_entry` PoP를 확인한다. R1은 ExitPermit·ExitGrant·target Descriptor hash를, R2는 EntryPermit·IngressGrant·`K_entry` 공개키를 받아서는 안 된다.
7. 두 grant와 PoP, data reservation, DATA_BIND가 끝난 뒤에만 C↔S DTLS와 6.3 `AUTH`를 수행한다. RAE는 이 exporter-bound AUTH를 대체하지 않는다.

`open_ref`는 C↔R1 control association 안에서만 유효한 16 byte CSPRNG 값이다. R1은 같은 `open_ref`의 byte-identical ADMISSION_OPEN에는 같은 ADMISSION_OPEN_OK만 재전달하며, 다른 bytes·다른 association에서의 재사용은 조용히 거부한다. C는 응답을 받기 전 같은 open request를 동일 bytes로 최대 세 번 재전송할 수 있다.

이 admission delivery는 signed Descriptor가 가리키는 정확한 S에 대한 제한된 envelope 전달 기능일 뿐이다. 각 R2는 rate/size/동시성 제한을 적용하고, 임의 address·port·payload 지속 전달 기능을 제공해서는 안 된다.

### 11.3.2 Split Admission Permit과 grant 발급

서로 독립된 EntryPermitIssuer와 ExitPermitIssuer는 S의 성공한 RAE 검증을 **relay target 비노출 authorization**으로 바꾼다. 두 permit의 Ed25519+ML-DSA-87 COSE_Sign payload는 다음과 같다.

| permit      | 정규 payload map                                                                                                                                                                      | 반드시 제외                                                                                                             |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| EntryPermit | `{0:"ob-entry-permit/1", 1:realm_id, 2:issuer_keyset, 3:permit_id_i, 4:issued, 5:expires, 6:profile, 7:k_entry_hash, 8:entry_context_token}`                                          | S endpoint/IP/Descriptor, C IP, R1/R2 ID·boot epoch, `permit_id_e`, `k_exit_hash`, `exit_context_token`, stable user ID |
| ExitPermit  | `{0:"ob-exit-permit/1", 1:realm_id, 2:issuer_keyset, 3:permit_id_e, 4:issued, 5:expires, 6:profile, 7:descriptor_hash, 8:directory_generation, 9:k_exit_hash, 10:exit_context_token}` | C IP, R1 ID·boot epoch, `permit_id_i`, `k_entry_hash`, `entry_context_token`, stable user ID                            |

role 5는 검증한 ServiceApproval에서 `realm_id`, `profile`, `k_entry_hash`, `entry_context_token`을 byte-for-byte 복사해서만 EntryPermit을 만들 수 있다. role 6은 `realm_id`, `profile`, `target_descriptor_hash`, `directory_generation`, `k_exit_hash`, `exit_context_token`을 byte-for-byte 복사해서만 ExitPermit을 만들 수 있다. 두 issuer는 이 binding field를 누락·변경·확장하거나 반대 permit field를 넣어서는 안 된다. `permit_id_i`와 `permit_id_e`만 각각 새 독립 16 byte CSPRNG 값이며, 서로 연결 가능한 공통 field, trace ID, nonce를 갖지 않는다. `issued`는 ServiceApproval의 `issued`보다 이르면 안 되고, `expires`는 ServiceApproval, issuer Delegation, 현재 Status, RAE expiry 중 가장 이른 값을 넘을 수 없다.

각 permit의 `profile`은 정확히 `0x06`이고 현재 Realm Delegation의 자기 role keyset이 서명한다. C는 EntryPermit을 R1에만, ExitPermit을 R2에만 제시한다. R1은 EntryPermit의 role 5 delegation·두 COSE signature·realm·profile·expiry·`K_entry` hash·자신의 현재 `entry_context_token`을 검증하고, R2는 ExitPermit의 role 6 delegation·두 COSE signature·Descriptor hash·directory generation·`K_exit` hash·자신의 현재 `exit_context_token`을 검증한다.

각 relay는 자기 context token과 permit ID를 하나의 원자적 단회 상태로 관리한다. context가 `UNUSED`일 때 처음 유효한 permit을 받으면 `(context_token, permit_id, SHA-384(raw_permit_cose_bytes))`를 결합해 **둘 다** `PENDING`으로 만든다. 같은 `PENDING` context는 정확히 같은 permit ID와 raw permit hash만 재전달할 수 있고, 다른 permit ID·다른 RAE에서 나온 permit·다른 raw bytes는 조용히 거부한다. `CONSUMED` context는 모든 permit을 거부한다. 따라서 하나의 `entry_context_token` 또는 `exit_context_token`은 하나의 live circuit에만 쓰인다.

유효한 permit이 처음 도착하면 relay는 정확히 하나의 grant와 challenge만 만든다. 같은 pending permit은 같은 grant/challenge만 재전달하며, 올바른 GrantProof가 승인될 때 결합된 permit과 context 상태가 함께 `CONSUMED`가 된다. challenge 뒤 10초 안에 승인되지 않으면 pending grant를 버리고, 아직 같은 pending permit에만 결합된 경우 permit과 context를 함께 `UNUSED`로 되돌릴 수 있다. context expiry, admission 취소, relay 재시작은 그 relay의 permit·context·control association 상태를 모두 무효화한다.

EntryPermit 검증 뒤 R1은 자기만 audience로 하는 role 3 `IngressGrantIssuer` keyset으로 IngressGrant를 만들고 C에게 RCT type 4로 보낸다. ExitPermit 검증 뒤 R2는 자기만 audience로 하는 role 4 `ExitGrantIssuer` keyset으로 ExitGrant를 만들고 C에게 RCT type 5로 보낸다. C가 permit을 제시할 때는 각각 RCT type 2와 type 3을 사용한다. 따라서 서비스/두 PermitIssuer는 R1을 알 필요가 없고 R1은 S를 알 필요가 없으며, R2만 자신에게 필요한 target Descriptor를 본다. Ingress와 Exit issuer keyset은 서로 독립적이어야 하며 각 grant는 해당 relay keyset의 Ed25519+ML-DSA-87 COSE_Sign으로 서명된 Deterministic CBOR payload다.

| grant        | 정규 payload map                                                                                                                                                                                                   | 반드시 제외                                                          |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| IngressGrant | `{0:"ob-ingress-grant/1", 1:realm_id, 2:issuer_keyset, 3:grant_id_i, 4:audience_r1, 5:r2_id, 6:r1_boot_epoch, 7:issued, 8:expires, 9:quota, 10:profile, 11:k_entry_hash}`                                          | S endpoint/IP, S Descriptor hash, C IP, stable user ID, `grant_id_e` |
| ExitGrant    | `{0:"ob-exit-grant/1", 1:realm_id, 2:issuer_keyset, 3:grant_id_e, 4:audience_r2, 5:r1_id, 6:r2_boot_epoch, 7:descriptor_hash, 8:directory_generation, 9:issued, 10:expires, 11:quota, 12:profile, 13:k_exit_hash}` | C IP/포트, stable user ID, `grant_id_i`                              |

`grant_id_i`와 `grant_id_e`는 서로 독립된 16 byte 난수다. `quota`는 정확히 one-live-circuit을 뜻한다. `K_entry`와 `K_exit`는 각각 새로 만든 hybrid PoP public key pair `[ed25519_public:32, mldsa87_public]`이고, `k_*_hash`는 이 배열의 Deterministic CBOR SHA-384다. 이 키는 계정 ID나 장기 device key가 아니며 grant마다 재사용할 수 없다.

R1은 자신이 발급한 IngressGrant를 PoP 때 다시 검증할 때 다음 모두 만족해야 한다: (1) `issuer_keyset`이 현재 검증된 Realm Delegation의 role 3이고 그 Delegation `audiences[]`가 정확히 자기 `endpoint_id`만 담으며, (2) COSE의 두 signature `kid`·algorithm·public key가 바로 그 하나의 delegated keyset과 일치하고, (3) `audience_r1`, `r2_id`, boot epoch, profile, 수명, quota가 현재 reservation과 일치하며, (4) issuer keyset·permit·grant·대상 Status가 모두 유효하고 폐기되지 않았다. R2는 같은 규칙에서 role 4, 자기 `endpoint_id`, `audience_r2`, R1, Descriptor hash·directory generation을 사용한다. role을 교차해 사용하거나 grant 자체에 적힌 issuer 주장만으로 신뢰해서는 안 된다. grant의 `expires`는 issuer Delegation, permit, RAE expiry를 모두 넘을 수 없다.

각 relay는 grant를 만들고 RCT 전송이 완료된 뒤 32 byte `relay_nonce`를 한 번 발급한다. C는 다음 context와 두 signature를 해당 control channel에서 보내야 한다.

```text
pop_context = Deterministic-CBOR([
  "Obelisk GrantPoP v1", SHA-384(grant_payload), grant_id,
  realm_id, audience_relay_id, relay_boot_epoch, relay_nonce, channel_role
])
E = DTLS-Exporter("EXPORTER-Obelisk-GrantPoP-v1", SHA-384(pop_context), 48)
proof_input = "Obelisk GrantPoP signature v1" || 0x00 || pop_context || E
proof = [Ed25519.Sign(K_ed, proof_input), ML-DSA-87.Sign(K_ml, proof_input)]
```

grant를 만든 relay는 작은 bootstrap record `GrantChallenge = Deterministic-CBOR(["Obelisk GrantChallenge v1", grant_id:16, relay_nonce:32])`를 보낸다. C는 RCT type 6으로 `GrantProof = Deterministic-CBOR(["Obelisk GrantProof v1", grant_id:16, public_key_pair, relay_nonce:32, proof])`를 보낸다. relay는 발급 당시 RAM에 보관한 정확한 grant payload를 사용하므로 C가 raw grant를 다시 보내게 해서는 안 된다. `channel_role`은 `0=entry`, `1=exit`이다. relay는 public key pair hash가 grant와 같은지, 두 signature가 유효한지, exporter가 현재 DTLS control association의 것인지 확인한다. relay nonce는 10초 안에 한 번만 사용 가능하다. 다른 DTLS association, 다른 relay, 다른 boot epoch, 다른 grant에서의 PoP 재사용은 실패한다. 승인 시 relay는 `GrantResult = Deterministic-CBOR(["Obelisk GrantResult v1", grant_id, 0])`만 보내며, 거부에는 `GrantResult`의 decision `1` 또는 일반 control failure만 사용한다.

grant는 `UNUSED → PENDING → CONSUMED` 단회 상태를 원자적으로 따라야 한다. R1/R2는 durable grant state를 만들지 않으며 RAM의 단일 사용 상태, 새 challenge, PoP, relay boot epoch를 함께 확인한다. relay 재시작 후 모든 기존 control·grant 상태·회선은 무효다. 서비스의 RAE/AppAuth 성공 결과나 원문은 릴레이에 전달하지 않고 최소 권한 grant만 전달한다.

### 11.3.3 R1↔R2 reservation control

R1↔R2 Relay Peer-Control에는 admission-only reservation과 data reservation 두 종류만 있다. admission-only request는 다음 Deterministic CBOR 배열이다.

```text
["Obelisk RelayAdmissionReserve v1", admission_ref:16,
 realm_id, r1_id, r2_id, r1_boot_epoch, expires]
```

R2의 수락 응답은 `["Obelisk RelayAdmissionReserve OK v1", admission_ref, r2_boot_epoch, r2_setup_port, expires]`다. R2는 이때 R1에 보내지 않는 새 `exit_context_token`을 자신의 admission ref state에만 보관한다. R1은 이 응답을 받은 뒤 C source tuple과 R2에 노출하지 않는 별도 `r1_setup_port`를 만든다. C에는 `r1_setup_port`만 알려 주며 `r2_setup_port`를 알려서는 안 된다. 이 reservation은 아래 SETUP_BIND가 끝나기 전에는 어떤 C↔R2 record도 R2로 전달하지 않으며, data port·S tuple·C↔S packet을 만들 수 없다.

`SETUP_BIND`는 C가 `r1_setup_port`에서 실제로 쓸 source tuple을 소유한다는 것을 C↔R1 Relay-Control exporter에 결합해 증명하는 4-record AEAD 절차다.

```text
C(new setup tuple) → R1 r1_setup_port: SETUP_BIND_INIT
R1                 → C(same tuple): SETUP_BIND_CHALLENGE
C(new setup tuple) → R1 r1_setup_port: SETUP_BIND_RESPONSE
R1                 → C(same tuple): SETUP_BIND_OK
R1: source tuple을 admission_ref에 원자적으로 결합한 뒤에만 R2로 forwarding
```

SETUP_BIND와 11.5 DATA_BIND는 같은 AEAD header enum을 사용한다. `direction`은 `0=C_TO_R1`, `1=R1_TO_C`이고, `kind`는 `0=INIT`, `1=CHALLENGE`, `2=RESPONSE`, `3=OK`다. C→R1에는 INIT와 RESPONSE만, R1→C에는 CHALLENGE와 OK만 유효하다. 각 새 bind에서 C→R1 sequence는 INIT `0`, RESPONSE `1`, R1→C sequence는 CHALLENGE `0`, OK `1`이며, 재전송은 반드시 같은 header·ciphertext·sequence를 사용한다. 다른 direction/kind 조합, 예상 밖 sequence, 같은 sequence의 다른 ciphertext, 만료·다른 상태의 record는 조용히 폐기한다. 유효한 duplicate INIT/RESPONSE에는 저장된 CHALLENGE/OK만 재전송하며 상태를 다시 만들지 않는다.

`setup_bind_context = Deterministic-CBOR(["Obelisk RelaySetupBind v1", realm_id, r1_endpoint_id, admission_ref, expires])`이고, `E = DTLS-Exporter("EXPORTER-Obelisk-RelaySetupBind-v1", SHA-384(setup_bind_context), 48)`, `PRK = HKDF-Extract(SHA-384, SHA-384(setup_bind_context), E)`다. `PRK`에서 HKDF-Expand한 방향별 AES-256-GCM key/IV label은 각각 `"Obelisk RelaySetupBind c2r key v1"`, `"Obelisk RelaySetupBind c2r iv v1"`, `"Obelisk RelaySetupBind r2c key v1"`, `"Obelisk RelaySetupBind r2c iv v1"`다. wire header/AAD는 `version:u8(1) || direction:u8 || kind:u8 || admission_ref:16 || sequence:u64be`이고, nonce는 해당 static IV와 `0x00000000 || sequence:u64be`의 XOR다. payload와 엄격한 datagram 형식은 바로 아래의 공통 Bind Record 규칙을 따른다.

`SETUP_BIND`와 `DATA_BIND`의 각 raw AEAD record는 `header || ciphertext` 하나만 든 UDP datagram 하나여야 한다. record coalescing과 IP fragmentation은 금지하며, UDP payload는 256 byte를 넘을 수 없다. SETUP header는 정확히 27 byte, DATA header는 정확히 31 byte다. AES-256-GCM ciphertext 길이에는 16 byte tag가 포함된다. 모든 payload는 Deterministic CBOR로 직렬화했을 때 아래의 정확한 길이를 가져야 한다.

| kind      | CBOR plaintext byte | ciphertext byte | SETUP UDP payload | DATA UDP payload |
| --------- | ------------------: | --------------: | ----------------: | ---------------: |
| INIT      |                 137 |             153 |               180 |              184 |
| CHALLENGE |                  79 |              95 |               122 |              126 |
| RESPONSE  |                  78 |              94 |               121 |              125 |
| OK        |                  72 |              88 |               115 |              119 |

`INIT`은 정확히 `Deterministic-CBOR(["init", client_nonce:32, pad:bytes])`이고 `pad`는 정확히 95 byte의 모두 0인 byte string이어야 한다. 이는 CHALLENGE ciphertext의 정확한 길이와 같아 response amplification을 만들지 않는다. CHALLENGE, RESPONSE, OK에는 임의 padding field나 추가 field가 허용되지 않는다. receiver는 allocation·AEAD open·CBOR parse 전에 datagram 길이, fixed header length, version/direction/kind, 현재 slot의 `admission_ref` 또는 `circuit_nonce`/`bind_epoch`, 그리고 예상 sequence를 확인해야 한다. 그 뒤 고정된 최대 153 byte ciphertext만 인증·복호화하고 canonical CBOR type·배열 길이·정확한 nonce·zero pad를 확인한다. 어떤 길이·header·AEAD·CBOR 오류도 state를 만들거나 큰 응답을 유발하지 않고 조용히 폐기한다.

R1은 현재 C↔R1 control association과 아직 만료되지 않은 admission ref에 맞고 AEAD가 유효한 INIT에만 5초 이하 pending bind를 만든다. 유효한 RESPONSE가 같은 source tuple에서 오기 전에는 R2로 datagram을 보내거나, R2 응답을 C에 전달하거나, 큰 오류를 보내서는 안 된다. 성공 뒤 R1은 source tuple을 admission ref에 원자적으로 결합하고 같은 tuple에 `SETUP_BIND_OK`를 보낸다. C는 정확한 client/relay nonce를 담은 OK를 검증한 뒤에만 Setup-DTLS를 시작한다. R1은 그 뒤 정확히 그 source tuple에서 온 datagram만 대응하는 `r2_setup_port`로 byte-for-byte 전달하고, R2의 응답도 그 tuple로만 되돌린다. tuple 변경·중복·만료·다른 control association은 새 admission/control association을 요구하며 조용히 거부한다.

R1은 EntryGrant와 `K_entry` PoP, 같은 admission의 `exit_ready_ref`를 검증한 뒤에만 현재 R1 Descriptor의 candidate인 새 `r1_data_ip`와 전용 `r1_data_port`를 먼저 예약한다. data reservation request는 다음 배열이다.

```text
[
  "Obelisk RelayDataReserve v1", reservation_ref:16, circuit_nonce:16,
  admission_ref:16, exit_ready_ref:16,
  realm_id, r1_id, r2_id, r1_boot_epoch,
  r1_data_ip:ip_bytes, r1_data_port:uint, profile:0x06, expires
]
```

R2는 ExitGrant와 `K_exit` PoP를 검증한 뒤에만 `["Obelisk RelayExitReady v1", admission_ref, exit_ready_ref:16, r2_boot_epoch, expires]`를 R1에 보낸다. 이 record에는 S tuple, Descriptor hash, ExitGrant, C identity를 넣어서는 안 된다. R2는 유효한 `exit_ready_ref`가 같은 admission ref·realm·R1·R2·boot epoch에 결합되고, `r1_data_ip`가 현재 서명된 R1 Descriptor의 candidate이며 `r1_data_port`가 0이 아닌 경우에만 data reservation을 수락한다. 수락 시 R2는 `r1_data_ip:r1_data_port`, `reservation_ref`, `circuit_nonce`, `exit_ready_ref`를 새 `r2_data_ip:r2_data_port` 및 정확한 S output tuple에 원자적으로 결합한다. `r2_data_ip`도 현재 R2 Descriptor candidate이고 port는 0이 아니어야 한다. R2의 data IP/port 선택은 realm, 자신의 local capacity, 무작위성에만 의존해야 하며 S 후보·Descriptor hash·서비스 종류에 의존해서는 안 된다. 수락 응답은 `["Obelisk RelayDataReserve OK v1", reservation_ref, r2_boot_epoch, r2_data_ip:ip_bytes, r2_data_port:uint, expires]`다.

각 `exit_ready_ref`는 R2 RAM에서 `UNUSED → PENDING → CONSUMED`를 따른다. 첫 유효 request는 raw request hash·`reservation_ref`·`circuit_nonce`·R1 data tuple을 결합해 PENDING이 되고, output tuple을 만들며 동일한 response를 저장한 뒤 CONSUMED가 된다. 같은 raw request만 저장한 response를 다시 받을 수 있고, 다른 request·tuple·nonce·reservation은 조용히 거부한다. R1도 같은 admission에 대해 하나의 data tuple과 `reservation_ref`만 만들고 동일 request만 재전송할 수 있다. R1은 `RelayDataReserve OK`를 받을 때 cached `reservation_ref`와 exact request, current admission의 `r2_boot_epoch`, R2 Descriptor candidate인 `r2_data_ip`, 0이 아닌 `r2_data_port`, expiry를 모두 확인한 뒤에만 그 정확한 R1→R2 tuple mapping을 원자적으로 활성화한다. 두 종류의 거부 응답은 각각의 type 문자열과 `ref`, `generic_code`만 담는다. 모든 ref와 `circuit_nonce`는 무작위이며 RAM에서만 존재한다.

R1은 R2의 수락 뒤에만 C↔R1 control로 다음 768 byte 이하의 `DATA_SLOT`을 보낸다.

```text
DATA_SLOT = [
  "Obelisk DataSlot v1", realm_id, admission_ref:16,
  r1_data_ip:ip_bytes, r1_data_port:uint,
  r2_endpoint_id, r2_descriptor_sha384:48,
  circuit_nonce:16, bind_epoch:uint, expires
]
```

이 절의 `r1_data_ip`와 `r2_data_ip`는 정확히 4 byte 또는 16 byte의 IP 주소 byte string이고, 모든 `*_data_port`는 1 이상 65,535 이하의 canonical CBOR unsigned integer다. `bind_epoch`도 0 이상 `2^32 - 1` 이하인 canonical CBOR unsigned integer이며 이 draft의 최초 값은 0이다. 같은 circuit nonce에서 `bind_epoch`를 증가하거나 재사용할 수 없다. C는 DATA_SLOT의 realm/admission/R2 ID·hash/expiry가 이미 검증한 OPEN_OK와 같고, `r1_data_ip`가 현재 R1 Descriptor candidate이며 port가 0이 아닌지 확인한 뒤에만 그 정확한 tuple로 DATA_BIND를 보낸다. R2 data IP·port, S tuple, ExitGrant는 DATA_SLOT에 넣어서는 안 된다.

R1→R2 request 및 R2→R1 response에는 C IP/port, C identity, `grant_id_i`, `K_entry`/hash, `opaque-path`, S endpoint, S Descriptor hash, ExitGrant, 서비스 인증 결과를 넣어서는 안 된다. R2는 response에 S 정보나 ExitGrant를 넣어서는 안 된다. 이 예약 참조는 data-plane header, CID, 로그, metrics, debug export, cross-domain 조사 자료로 사용할 수 없다.

### 11.4 회선 설정

1. C는 C↔R2 Setup-DTLS에서 RCT type 3으로 ExitPermit을 제시한다. R2는 permit과 정확한 Descriptor hash·length·directory generation·quota를 검증한 뒤 ExitGrant를 RCT type 5로 C에 보낸다. C가 RCT type 6 `GrantProof`로 `K_exit` PoP를 보이면 R2는 port를 예약하지 않은 `exit_ready_ref`만 R1에 보낸다.
2. C는 C↔R1 Relay-Control에서 RCT type 2로 EntryPermit을 제시한다. R1은 permit을 검증해 IngressGrant를 RCT type 4로 C에 보내고 C의 RCT type 6 `GrantProof`로 된 `K_entry` PoP를 검증한다. R1은 같은 admission ref에 대한 유효한 `exit_ready_ref`가 있을 때만 다음 단계로 간다.
3. R1은 새 전용 R1 data source tuple을 먼저 예약하고, R1↔R2 control로 `exit_ready_ref`에 결합된 byte-identical data reservation을 요청한다. R2는 이 시점에만 정확한 R1 source tuple, data port, exact S candidate에 대한 회선별 output tuple을 만든다.
4. R1은 R2 수락 뒤에만 이미 살아 있는 C↔R2 Setup과 별도의 `DATA_SLOT`(`circuit_nonce`, `bind_epoch=0` 포함)을 C↔R1 control로 C에 보낸다. 실제 C data tuple은 다음 DATA_BIND와 `DATA_BIND_OK`가 성공하기 전까지 활성화되지 않는다.
5. `DATA_BIND_OK`를 받은 뒤에만 C는 C↔S DTLS handshake를 data path로 시작한다. ClientHello에는 SNI, endpoint 식별자/hash, 서비스별 ALPN, endpoint별 ticket identity를 넣지 않는다.

admission setup slot과 C↔R2 Setup-DTLS state는 `ADMISSION_OPEN_OK.expires` 또는 생성 뒤 90초 중 먼저 오는 때까지 유지한다. 이 시간은 RAE, capsule, permit, grant의 RCT 전송 전체에 공유되는 end-to-end deadline이며, 개별 RCT의 30초 한도를 줄이지 않는다. `DATA_SLOT`의 `expires`는 발급 뒤 30초를 넘을 수 없고 admission/grant 만료를 넘어설 수 없다. R1/R2의 port pool이 부족하면 명시적으로 `CIRCUIT_CAPACITY`를 반환하고, CID·공유 route label·임의 목적지 fallback을 사용해서는 안 된다. R1→R2 data leg와 R2→S data leg는 회선별 고유 tuple/port로 할당하고, port나 slot ID에 사용자·대상·grant 의미를 넣어서는 안 된다.

### 11.5 DATA_BIND

DATA_BIND는 C가 새 data UDP source tuple의 실제 소유자임을 R1에 증명하는 초기 4-record 절차다. 이는 C↔R1 Relay-Control DTLS exporter로 만든 전용 AEAD record이며, C↔S application data도 Obelisk Packet도 아니다.

```text
C(new data tuple) → R1 data slot: DATA_BIND_INIT
R1               → C(same tuple): DATA_BIND_CHALLENGE
C(new data tuple) → R1 data slot: DATA_BIND_RESPONSE
R1               → C(same tuple): DATA_BIND_OK
R1: tuple mapping을 원자적으로 활성화
```

`bind_context`는 다음 Deterministic CBOR 배열이고, `E`는 C↔R1 Relay-Control DTLS exporter 결과다.

```text
bind_context = [
  "Obelisk RelayBind v1", realm_id, r1_endpoint_id, r2_endpoint_id,
  r2_descriptor_sha384, admission_ref, r1_data_ip, r1_data_port,
  circuit_nonce, bind_epoch, expires
]
E   = DTLS-Exporter("EXPORTER-Obelisk-RelayBind-v1", SHA-384(bind_context), 48)
PRK = HKDF-Extract(SHA-384, SHA-384(bind_context), E)
```

`PRK`에서 HKDF-Expand로 방향별 `AES-256-GCM` key 32 byte와 static IV 12 byte를 각각 유도한다. label은 정확히 `"Obelisk RelayBind c2r key v1"`, `"Obelisk RelayBind c2r iv v1"`, `"Obelisk RelayBind r2c key v1"`, `"Obelisk RelayBind r2c iv v1"`다.

wire header는 다음과 같으며 AAD다.

```text
version:u8(1) || direction:u8 || kind:u8 || circuit_nonce:16 ||
bind_epoch:u32be || sequence:u64be
```

nonce는 `static_iv XOR (0x00000000 || sequence:u64be)`다. direction/kind/sequence와 duplicate 처리 규칙은 11.3.3의 공통 enum을 정확히 따른다. ciphertext는 AES-256-GCM으로 보호한 Deterministic CBOR payload다.

- `INIT` payload: `["init", client_nonce:32, pad:bytes]`이며 `pad`는 정확히 95 byte의 0이어야 한다. 전체 record 길이와 추가 field 금지는 11.3.3의 공통 Bind Record 규칙을 따른다.
- `CHALLENGE` payload: `["challenge", client_nonce:32, relay_nonce:32]`
- `RESPONSE` payload: `["response", client_nonce:32, relay_nonce:32]`
- `OK` payload: `["ok", client_nonce:32, relay_nonce:32]`

R1은 grant·epoch·AEAD·source tuple을 검증한 뒤 하나의 pending bind만 5초 이하로 보관한다. INIT가 최소 길이보다 작으면 challenge를 보내지 않는다. R1은 challenge를 관찰된 source tuple에만 보내고, 검증 전에는 R2/S로 어떤 data도 전달하지 않는다. 올바른 RESPONSE가 같은 source tuple에서 오면 그 tuple을 data slot에 원자적으로 결합하고 같은 tuple에 DATA_BIND_OK를 보낸다. C는 DATA_SLOT의 circuit/epoch/expiry와 exact client/relay nonce를 가진 OK를 검증한 뒤에만 C↔S DTLS handshake를 시작한다. duplicate RESPONSE에는 저장한 OK만 재전송한다. 실패·만료·중복·모르는 slot은 응답 없이 폐기하거나 이미 인증된 control channel에 일반 코드 `BIND_FAILED`만 알린다. 성공 후 tuple 변경은 이 절차로 갱신할 수 없고, 새 회선과 새 C↔S DTLS 연관을 만들어야 한다.

### 11.6 데이터 전달과 수명

- R1/R2는 예상한 source tuple에서 온 입력 datagram 하나를 출력 datagram 하나로만 매핑한다. 모르는 tuple·만료 slot·잘못된 grant는 응답 없이 폐기한다. payload decode, reassembly, retransmission, ACK 생성, Obelisk frame 검사, CID route key 사용은 금지한다. ECN은 단조 보존하고, DSCP는 중립값으로 정규화한다.
- R1은 R1→R2 leg의 모든 datagram을 수락된 정확한 `r1_data_ip:r1_data_port`에서만 보내고, R2는 그 exact source tuple 외의 입력을 절대로 그 회선에 매핑해서는 안 된다. R2→R1 응답도 수락된 정확한 `r2_data_ip:r2_data_port`에서만 보내며, R1은 다른 source tuple을 C에 전달해서는 안 된다.
- R2는 ExitGrant가 승인한 정확한 현재 Descriptor 후보 외의 UDP 목적지로 보내서는 안 된다.
- Relay Privacy data path의 `P`는 `Obelisk/1-draft.0`에서 각 방향 1,200 byte로 고정한다. `B`는 7.1.1의 실제 DTLS overhead를 뺀 값이며, 각 relay는 IP fragmentation을 하지 않는다. raw ICMP 인용 packet·원본 tuple·원본 주소를 C에 전달해서는 안 된다. relay 경로의 MTU 증가에는 양 relay control plane으로 검증된 per-leg 상한을 안전하게 전달하는 차기 wire version이 필요하다.
- relay data circuit은 어느 방향에서도 유효하게 전달한 UDP datagram이 마지막으로 관찰된 뒤 120초가 지나면 만료한다. R1/R2는 C↔S DTLS 또는 Obelisk를 해독하지 않으므로 C/S의 PTO를 추론하거나 relay 만료 조건에 사용해서는 안 된다. C와 S는 각자 local PTO·연결 종료·재접속을 독립적으로 판단한다. 절대 수명은 8시간이다.
- admission setup slot과 C↔R2 Setup-DTLS state는 C↔S가 ACTIVE가 되는 즉시, 또는 `ADMISSION_OPEN_OK.expires`나 생성 뒤 90초 중 먼저 오는 시점에 폐기한다. `DATA_SLOT` 및 아직 결합되지 않은 data tuple은 DATA_SLOT의 30초 expiry에 폐기한다.
- C↔R1 control은 마지막 circuit 종료 뒤 5분 유휴 시 만료한다.
- 기본 keepalive는 없다. 애플리케이션이 `maintain_path`를 명시한 경우에만 25초 유휴 뒤 제어/경로 liveness probe를 보낼 수 있다.
- relay의 application payload queue는 0이다. OS 송신 queue가 가득 차면 즉시 drop하며 저장·재전송하지 않는다.
- Relay Privacy에서 허용하는 C↔S 재개 ticket identity는 정확히 32 byte의 단회 무작위·비의미적 값이어야 한다. endpoint, realm 외부 account, grant, circuit, R1/R2, 서비스 이름을 인코딩하거나 장기 재사용해서는 안 된다. ticket은 새 C↔S ClientHello의 SNI/ALPN 제약을 완화하지 않으며 RAE admission에 사용할 수 없다.
- relay 재시작, R1↔R2 data pair 실패, NAT 주소 변화는 새 grant/새 circuit/새 DTLS handshake 또는 허용된 ticket 재개를 요구한다. 투명한 연관 이동은 없다. relay data tuple, port, slot, circuit mapping은 끝난 뒤 정확히 30초의 relay-local quarantine이 끝나기 전에는 재사용해서는 안 된다. 이 고정 quarantine은 C↔S의 PTO나 endpoint transport state를 읽거나 추론하지 않는다. 두 홉 경로가 실패해도 단일 relay, 같은 privacy domain, 직접 경로로 자동 하향해서는 안 된다. 애플리케이션이 별도 연결을 명시적으로 선택할 수는 있지만 기존 Obelisk state, ticket, circuit을 재사용해서는 안 된다.

## 12. 리소스·운영 프라이버시

### 12.1 회선과 메시지 한도

| 항목                                           |                                                          값 |
| ---------------------------------------------- | ----------------------------------------------------------: |
| Ingress/Exit Grant 수명                        |                                                        90초 |
| admission setup slot 수명                      | 최대 90초, `ADMISSION_OPEN_OK.expires` 및 grant expiry 이하 |
| DATA_SLOT 수명                                 |              발급 뒤 최대 30초, admission/grant expiry 이하 |
| data circuit idle                              |                      마지막 유효 전달 UDP datagram 뒤 120초 |
| data circuit 절대 수명                         |                                                       8시간 |
| RMSG 최대 길이                                 |                                                       1 MiB |
| 동시 불완전 RMSG                               |                                                          16 |
| 총 RMSG 조립 메모리                            |                                                       8 MiB |
| RMSG 조립 수명                                 |                                                        60초 |
| RMSG 조각 수                                   |                                                  최대 2,048 |
| 방향별 unretired RMSG                          |                                                  최대 1,024 |
| 방향별 DATAGRAM topic                          |                                                  최대 1,024 |
| association·수신 방향별 RCT terminal tombstone |                                  최대 16개, metadata 16 KiB |
| relay process 전체 RCT terminal tombstone      |                                최대 4,096개, metadata 2 MiB |
| C↔R2 Setup association당 live RAE route key    |                                             정확히 최대 1개 |
| R2 process 전체 live RAE route key             |                                최대 4,096개, metadata 2 MiB |
| relay payload queue                            |                                                           0 |

source IP별 admission rate, circuit quota, port pool 크기는 relay의 로컬 적응 정책이다. 이 값들은 신뢰 경계 밖으로 노출하거나 두 relay 도메인 사이에 공유해서는 안 된다.

### 12.2 로그와 측정

- R1은 C IP/tuple과 R2 관련 원시 운영 기록을 자신의 도메인에서 최대 24시간 암호화 보관할 수 있다.
- R2는 R1과 S tuple 관련 원시 운영 기록을 자신의 도메인에서 최대 24시간 암호화 보관할 수 있다.
- join 가능한 grant/permit ID, stable user ID, CID dump, trace ID, payload hash, 계정 식별자, `admission_ref`, `circuit_nonce`, reservation reference, slot mapping, RCT `transfer_id`, `entry_context_token`, `exit_context_token`을 두 relay 도메인이 공유해서는 안 된다. relay의 `admission_ref`, `circuit_nonce`, reservation reference, slot mapping, transfer ID, 두 context token은 RAM 전용이며 영속 log, telemetry, debug export에 남겨서는 안 된다. ServiceApproval의 `approval_id`와 `rae_sha384`는 issuer의 단회 상태에 필요한 최소 hash/index로만 expiry 뒤 30초까지 보관할 수 있고, relay 또는 cross-domain telemetry에는 남겨서는 안 된다.
- payload, C↔S 인증 envelope, grant 원문, key material, Endpoint Descriptor 원문, packet capture는 telemetry에 남겨서는 안 된다. incident debug capture는 기본 비활성이며, 두 도메인의 독립 승인과 감사 기록이 있을 때만 제한적으로 허용된다.
- 집계되고 비결합 가능한 운영 측정값은 최대 30일 보관할 수 있다.
- 도메인 간 조사에는 각 도메인의 독립적인 두 사람 승인과 감사 기록이 필요하다.

## 13. 종료와 재접속

종단은 오류를 감지하면 가능한 경우 하나의 `CONNECTION_CLOSE`를 보내고 local state를 폐기한다. 공격성 입력에는 close 없이 조용히 drop하는 것이 허용된다. Direct Core 연관의 endpoint tuple과 CID는 종단이 아는 `max(3 × PTO, 30초)` quiet period가 끝날 때까지 재사용할 수 없다. Relay Privacy의 relay data tuple, port, slot, circuit mapping에는 endpoint PTO를 적용하지 않으며 11.6의 정확히 30초 relay-local quarantine만 적용한다.

|     코드 | 이름                             |
| -------: | -------------------------------- |
| `0x0000` | NO_ERROR                         |
| `0x0001` | PROTOCOL_VIOLATION               |
| `0x0002` | FRAME_ENCODING_ERROR             |
| `0x0003` | UNSUPPORTED_CRITICAL_FRAME       |
| `0x0004` | FLOW_CONTROL_ERROR               |
| `0x0005` | STREAM_STATE_ERROR               |
| `0x0006` | RMSG_LIMIT_ERROR                 |
| `0x0007` | AUTHENTICATION_FAILED            |
| `0x0008` | IDENTITY_VALIDATION_FAILED       |
| `0x0009` | POLICY_REJECTED                  |
| `0x000a` | ECN_UNAVAILABLE                  |
| `0x000b` | PATH_MTU_ERROR                   |
| `0x000c` | CONNECTION_TIMEOUT               |
| `0x000d` | DUPLICATE_ASSOCIATION            |
| `0x000e` | UDP_UNAVAILABLE                  |
| `0x000f` | PATH_UNAVAILABLE                 |
| `0x0010` | REPLAY_DETECTED                  |
| `0x0011` | INTERNAL_ERROR                   |
| `0x0012` | UNSUPPORTED_VERSION              |
| `0x0100` | GRANT_REJECTED (Relay Profile)   |
| `0x0101` | CIRCUIT_CAPACITY (Relay Profile) |
| `0x0102` | BIND_FAILED (Relay Profile)      |

Core의 재접속은 새 연관이다. stream offset, RMSG receipt 상태, DATAGRAM generation, congestion state, CID, relay circuit은 이어지지 않는다. ticket 재개는 transport handshake를 줄일 수 있을 뿐 이전 애플리케이션 작업의 결과를 보장하지 않는다.

Core는 UDP-only다. `UDP_UNAVAILABLE` 또는 `PATH_UNAVAILABLE` 뒤 애플리케이션은 별도의 HTTPS fallback을 선택할 수 있지만, 그 fallback은 Obelisk의 key, ticket, stream, receipt, congestion state를 공유해서는 안 된다.

## 14. 보안·프라이버시 고려 사항

1. DTLS는 Obelisk가 직접 구현하는 암호가 아니라 검증된 DTLS 1.3 구현체가 처리해야 한다. 자체 AEAD·HKDF 사용은 RelayBind처럼 이 문서가 정확히 정의한 좁은 control record에 한정하고, 별도 암호 감사를 받아야 한다.
2. Relay Privacy는 R1/R2 비공모 가정의 프라이버시 개선책이다. 트래픽 패턴, 전역 관찰자, endpoint fingerprinting을 없애지 않는다.
3. raw UDP를 제공하지 않는 브라우저는 Core peer가 아니다. HTTPS Gateway는 최종 서비스 대상 application ciphertext를 불투명하게 다뤄야 하며, gateway 종료 TLS를 C↔S E2EE라고 불러서는 안 된다.
4. 인증서 pin, Directory, Status가 현재여야 한다. 오래된 Status에서 새 연결을 허용하는 것은 폐기 회피 공격을 만든다.
5. ECN·DPLPMTUD·CID/RRC는 OS와 DTLS 라이브러리 지원에 의존한다. 지원되지 않는 필수 기능을 조용히 비활성화하는 구현은 이 명세에 부합하지 않는다.
6. RMSG receipt는 영구적 업무 완료 영수증이 아니다. 결제, 발송, 권한 변경처럼 부작용이 있는 작업은 애플리케이션 idempotency key와 별도 영구 확인 절차를 사용해야 한다.
7. 오류 문자열, SNI, endpoint별 ALPN, 장기 CID, cross-domain trace ID는 metadata 누출을 키운다. 이 명세가 금지한 곳에서는 디버그 모드도 예외가 아니다.

## 15. 구현 적합성 게이트

구현체가 “Obelisk/1-draft.0 지원”이라고 주장하려면 적어도 다음을 자동 시험과 상호운용성 시험으로 입증해야 한다.

1. OVINT 최소 인코딩, 모든 frame 길이, 64-frame 상한, `P/O/B` 경계와 padding bucket, 오류 상태 기계를 fuzzing과 property test로 검증한다.
2. `TLS_AES_256_GCM_SHA384`, `SecP384r1MLKEM1024`, ML-DSA-87 self-signed cert, Descriptor SPKI pin, 양방향 Direct S2S client auth와 1,200 byte 이하 DTLS handshake fragmentation을 실제 DTLS 라이브러리에서 시험한다.
3. `draft-ietf-tls-mldsa-06` 의존성의 실제 codepoint·동작을 고정하고, 최종 RFC 변경 시 재검증한다.
4. IdentityConfirm의 raw `ctx_bytes` exporter binding과 outer CBOR type, ServerHello의 실제 PSK 선택에 따른 `handshake_kind`, ticket CAS 경쟁·PENDING의 exact ClientHello/tuple 재전송과 다른 tuple 거부, server restart 무효화, `psk_dhe_ke`, 0-RTT 거부, KeyUpdate ACK 전 current/new epoch 경계를 시험한다.
5. 고손실·재정렬·중복, 64개 ACK range 상한과 초기 `B=1,024`에서 들어가는 61개 range 절단, ACK-only packet이 congestion window를 막지 않는 단방향 전송, ACK 또는 loss에서 bytes-in-flight가 정확히 한 번 해제되는지, PTO 6회, RMSG의 out-of-order terminal watermark·outcome PTO·ledger 포화·overlap 불일치, stream reset, ECN ACK counter 재정렬의 관찰 가능한 동작을 시험한다.
6. CUBIC/HyStart++, pacing, ECT(0) 검증, CE 보존, DPLPMTUD probe와 ICMP 없는 PMTU black-hole downshift, `P` 하향 뒤 신뢰성 frame 재분할, IP fragmentation 금지를 실제 IPv4/IPv6 경로에서 시험한다.
7. 직접 이동에서 RFC 9146 CID와 RFC 9853 Enhanced RRC를 실제로 지원하는 DTLS 구현체인지, 모든 replacement CID가 12 byte·global demux scope에서 비중복인지, active/spare/grace 1/2/2 및 vector/request 상한이 allocation 전 적용되는지, `RequestConnectionId`가 대응 `NewConnectionId`로 fulfilled되기 전 재요청되지 않는지, 양쪽 Basic RRC path state reset·old-ledger retire·late old-path ACK 격리가 맞는지 시험한다. 지원하지 않으면 non-migratable로 표시해야 한다.
8. Revocation Ledger의 inclusion·consistency 검증을 RFC 9162의 알고리즘 순서와 SHA-384 `N` 치환으로 시험한다. 최소 `0 < old_size < new_size ≤ 64`의 모든 쌍, power-of-two old size, 같은 size의 root 변경, Status/checkpoint 60초 freshness 경계를 포함해야 한다.
9. RCT의 768 byte 경계, `RCT_ACK.received_ranges`의 정확한 nested-CBOR 문법, 순서 변경·중복·모든 partial overlap 불일치, 64 KiB/30초 한도, fragment record ledger의 Karn RTT·loss/BIF/CUBIC/PTO 처리, fragment·`RCT_COMPLETE`/`RCT_COMPLETE_ACK` 손실, terminal tombstone/map quota 포화와 transfer-ID conflict 무상태 처리, semantic retry의 byte-identical 결과, IP fragmentation 금지를 네트워크 손실 주입으로 시험한다.
10. 두 릴레이에서 C IP와 S endpoint의 상호 비노출, split grant audience/PoP, OPEN_OK의 exact R2 pinning, setup/data slot 분리, SETUP_BIND·DATA_BIND의 고정 record 길이·zero pad·OK·source-tuple 검증, exact R1/R2 data tuple과 exit-ready 단회 소비, context token의 다른 admission 또는 다른 RAE/permit 재사용 거부와 token·permit의 원자적 timeout rollback, RAE route-key 충돌·만료·quota·다른 C↔R2 association capsule 전달 거부, ECN 보존, arbitrary UDP proxy 차단을 패킷 캡처와 침투 시험으로 확인한다.
11. ServiceApproval의 role 7 Descriptor audience·Revocation·모든 bound field와 COSE protected `content type`/payload type binding 검증, 다른 target/RAE/reply key/PoP key/profile/expiry 치환 거부, AdmissionPermit capsule의 raw-RAE directory generation·expiry binding, `[approval_id, rae_sha384]` CAS 경쟁과 재시작 fail-closed, Entry/ExitPermitIssuer 한쪽만 침해된 경우의 양쪽 permit 발급 불가를 시험한다.
12. 독립 암호 감사, DoS/resource exhaustion 평가, 장시간 부하 시험, 장애·재시작·port pool 고갈 훈련을 마친다.

이 게이트를 통과하지 않은 구현은 이 문서를 설계 목표로만 인용할 수 있으며, production-ready 또는 완전한 상호운용성이라고 주장해서는 안 된다.

## 16. 참고 규격

- [RFC 8085 — UDP Usage Guidelines](https://www.rfc-editor.org/rfc/rfc8085.html)
- [RFC 8899 — Datagram Packetization Layer PMTU Discovery](https://www.rfc-editor.org/rfc/rfc8899.html)
- [RFC 9147 — DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147.html)
- [RFC 9146 — DTLS Connection ID](https://www.rfc-editor.org/rfc/rfc9146.html)
- [RFC 9853 — Enhanced Record and Replay Control for DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9853.html)
- [RFC 10024 — PQ Hybrid Key Exchange in TLS](https://www.rfc-editor.org/rfc/rfc10024.html)
- [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — ML-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [RFC 9881 — ML-DSA in X.509](https://www.rfc-editor.org/rfc/rfc9881.html)
- [draft-ietf-tls-mldsa-06](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/)
- [RFC 8949 — CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [RFC 9000 — QUIC Transport](https://www.rfc-editor.org/rfc/rfc9000.html) (ECN validation 알고리즘의 참고만 하며 QUIC을 사용하지 않음)
- [RFC 9052 — COSE](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC 9964 — ML-DSA in COSE](https://www.rfc-editor.org/rfc/rfc9964.html)
- [RFC 9162 — Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html)
- [RFC 9438 — CUBIC](https://www.rfc-editor.org/rfc/rfc9438.html)
- [RFC 9406 — HyStart++](https://www.rfc-editor.org/rfc/rfc9406.html)
- [RFC 9002 — QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002.html) (복구 알고리즘의 참고만 하며 QUIC을 사용하지 않음)
