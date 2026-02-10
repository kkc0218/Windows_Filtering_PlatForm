#pragma once

// ============================================================================
// Kernel Mode / User Mode 분기
// ============================================================================
#ifdef __KERNEL_MODE__
    // Kernel Mode - WDK 헤더 사용
#include <ntdef.h>
#else
    // User Mode - Windows SDK 헤더 사용
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#endif

// ============================================================================
// 디바이스 이름 정의
// ============================================================================
#define DEVICE_NAME         L"\\Device\\WfpExampleDevice"
#define SYMBOLIC_LINK_NAME  L"\\??\\WfpExampleLink"

// ============================================================================
// GUID 정의 - WFP Callout 식별자
// ============================================================================


#ifdef __KERNEL_MODE__

// 기본 차단 Callout (ALE_AUTH_CONNECT_V4)
// {B180900E-B939-4E64-912A-63799634B03B}
DEFINE_GUID(GUID_MY_WFP_CALLOUT,
    0xb180900e, 0xb939, 0x4e64, 0x91, 0x2a, 0x63, 0x79, 0x96, 0x34, 0xb0, 0x3b);

// SNI Stream Callout (STREAM_V4) - TLS ClientHello SNI 파싱용
// {C291A11F-CA4A-4F75-A23B-74889735C14C}
DEFINE_GUID(GUID_MY_WFP_SNI_CALLOUT,
    0xc291a11f, 0xca4a, 0x4f75, 0xa2, 0x3b, 0x74, 0x88, 0x97, 0x35, 0xc1, 0x4c);

// QUIC 차단 Callout (DATAGRAM_DATA_V4) - QUIC Initial 패킷 SNI 파싱용 (v3.0 신규)
// {D382B22F-E5B1-4C6F-B430-56789ABCDE01}
DEFINE_GUID(GUID_MY_WFP_QUIC_CALLOUT,
    0xd382b22f, 0xe5b1, 0x4c6f, 0xb4, 0x30, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0x01);

// DNS 모니터링 Callout (DATAGRAM_DATA_V4) - DNS 응답 모니터링용 (v3.0 신규)
// {E493C330-F6C2-4D70-C541-67890BCDEF12}
DEFINE_GUID(GUID_MY_WFP_DNS_CALLOUT,
    0xe493c330, 0xf6c2, 0x4d70, 0xc5, 0x41, 0x67, 0x89, 0x0b, 0xcd, 0xef, 0x12);

// ALE Flow Established Callout (v3.0 신규)
// {F5A4D441-A7E3-5E81-D652-789A1CDEF023}
DEFINE_GUID(GUID_MY_WFP_FLOW_CALLOUT,
    0xf5a4d441, 0xa7e3, 0x5e81, 0xd6, 0x52, 0x78, 0x9a, 0x1c, 0xde, 0xf0, 0x23);

// DNS Sinkhole Callout (v3.0 신규) - DNS 응답 수정용
// {A6B5E552-B8F4-6F92-E763-89AB2DEF1234}
DEFINE_GUID(GUID_MY_WFP_DNS_SINKHOLE_CALLOUT,
    0xa6b5e552, 0xb8f4, 0x6f92, 0xe7, 0x63, 0x89, 0xab, 0x2d, 0xef, 0x12, 0x34);

#endif // __KERNEL_MODE__

// ============================================================================
// IOCTL 코드 정의
// ============================================================================

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

// 기본 PID 차단 관련
#define IOCTL_WFP_SET_BLOCK_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 패킷 캡처 토글 (On/Off)
#define IOCTL_WFP_TOGGLE_CAPTURE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 배치 패킷 데이터 조회
#define IOCTL_WFP_GET_PACKET_BATCH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 캡처 상태 조회
#define IOCTL_WFP_GET_CAPTURE_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 패킷 큐 초기화 (클리어)
#define IOCTL_WFP_CLEAR_PACKET_QUEUE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 차단 해제 (PID 리셋)
#define IOCTL_WFP_RESET_BLOCK_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// SNI 기반 URL 차단 IOCTL 코드
// ============================================================================

// SNI URL 차단 추가/제거 (토글)
#define IOCTL_WFP_SNI_BLOCK_URL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

// SNI 차단 리스트 조회
#define IOCTL_WFP_SNI_GET_BLOCK_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

// SNI 차단 리스트 전체 초기화
#define IOCTL_WFP_SNI_CLEAR_BLOCK_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

// SNI 차단 활성화/비활성화
#define IOCTL_WFP_SNI_TOGGLE_BLOCKING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// 확장 IOCTL 코드 
// ============================================================================

// 확장 상태 조회 (QUIC/DNS 통계 포함)
#define IOCTL_WFP_GET_CAPTURE_STATUS_EX \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IP 캐시 조회 (디버그)
#define IOCTL_WFP_GET_IP_CACHE_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IP 캐시 초기화
#define IOCTL_WFP_CLEAR_IP_CACHE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// DNS Sinkhole IOCTL 
// ============================================================================

// DNS 싱크홀 활성화/비활성화
#define IOCTL_WFP_DNS_SINKHOLE_TOGGLE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)

// DNS 싱크홀 IP 설정
#define IOCTL_WFP_DNS_SINKHOLE_SET_IP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)

// DNS 싱크홀 상태 조회
#define IOCTL_WFP_DNS_SINKHOLE_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// 상수 정의
// ============================================================================

// 패킷 캡처 관련
#define MAX_PACKETS_PER_BATCH   64      // 배치당 최대 패킷 수
#define PACKET_QUEUE_SIZE       256     // 드라이버 내부 큐 크기 (링 버퍼)

// SNI 차단 관련
#define MAX_SNI_LENGTH          256     // 최대 SNI 도메인 길이
#define MAX_BLOCKED_URLS        128     // 최대 차단 URL 수
#define SNI_BLOCK_LIST_SIZE     32      // 한 번에 반환할 차단 URL 수

// IP 캐시 관련 상수 (v3.0 신규) - Kernel Mode에서 재정의 방지
#ifndef MAX_BLOCKED_IPS
#define MAX_BLOCKED_IPS         2048    // 차단 IP 캐시 크기
#endif

#ifndef IP_CACHE_TIMEOUT_SEC
#define IP_CACHE_TIMEOUT_SEC    1800    // IP 캐시 만료 시간 (30분)
#endif

// QUIC 프로토콜 관련 상수 (v3.0 신규)
#ifndef QUIC_VERSION_1
#define QUIC_VERSION_1          0x00000001
#endif

#define QUIC_VERSION_2          0x6b3343cf

#ifndef QUIC_LONG_HEADER_MASK
#define QUIC_LONG_HEADER_MASK   0x80
#endif

#ifndef QUIC_INITIAL_TYPE
#define QUIC_INITIAL_TYPE       0x00
#endif

#define QUIC_DEFAULT_PORT       443

// DNS 관련 상수 (v3.0 신규)
#define DNS_PORT                53
#define DNS_RESPONSE_FLAG       0x8000
#define DNS_MAX_NAME_LENGTH     255

// DNS Sinkhole 상수 (v3.0 신규)
#define DNS_SINKHOLE_DEFAULT_IP     0x7F000001  // 127.0.0.1 (호스트 바이트 오더)
#define DNS_SINKHOLE_HTTPS_PORT     443
#define DNS_SINKHOLE_HTTP_PORT      80

// ============================================================================
// 프로토콜 상수 (IPPROTO_*)
// ============================================================================
#define PROTO_ICMP      1
#define PROTO_TCP       6
#define PROTO_UDP       17

// ============================================================================
// 패킷 방향 열거
// ============================================================================
typedef enum _PACKET_DIRECTION {
    PACKET_DIR_OUTBOUND = 0,    // 송신 패킷
    PACKET_DIR_INBOUND = 1      // 수신 패킷
} PACKET_DIRECTION;

// ============================================================================
// 패킷 액션 열거
// ============================================================================
typedef enum _PACKET_ACTION {
    PACKET_ACTION_PERMIT = 0,   // 허용
    PACKET_ACTION_BLOCK = 1     // 차단됨
} PACKET_ACTION;

// ============================================================================
// 차단 타입 열거 (v3.0 신규)
// ============================================================================
typedef enum _BLOCK_TYPE {
    BLOCK_TYPE_NONE = 0,        // 차단 없음
    BLOCK_TYPE_PID = 1,         // PID 기반 차단
    BLOCK_TYPE_IP_CACHE = 2,    // IP 캐시 기반 차단
    BLOCK_TYPE_SNI_TLS = 3,     // TLS SNI 기반 차단
    BLOCK_TYPE_SNI_QUIC = 4,    // QUIC SNI 기반 차단
    BLOCK_TYPE_DNS = 5,         // DNS 기반 차단
    BLOCK_TYPE_DNS_SINKHOLE = 6 // DNS 싱크홀 리다이렉션 (v3.0 신규)
} BLOCK_TYPE;

// ============================================================================
// 공유용 구조체 정의
// ============================================================================

#pragma pack(push, 8)  // 8바이트 정렬로 32/64비트 호환성 보장

// 기본 PID 차단 설정 구조체
typedef struct _BLOCK_CONFIG {
    unsigned long ProcessId;
    unsigned long Reserved;     // 정렬용 패딩
} BLOCK_CONFIG, * PBLOCK_CONFIG;

// 캡처 토글 설정 구조체
typedef struct _CAPTURE_TOGGLE {
    unsigned long Enable;       // 0: 비활성화, 1: 활성화
    unsigned long Reserved;     // 정렬용 패딩
} CAPTURE_TOGGLE, * PCAPTURE_TOGGLE;

// 캡처 상태 조회 응답 구조체 (기본 - 하위 호환성 유지)
typedef struct _CAPTURE_STATUS {
    unsigned long IsCapturing;      // 현재 캡처 여부
    unsigned long BlockedPid;       // 현재 차단 중인 PID
    unsigned long QueuedPackets;    // 큐에 대기 중인 패킷 수
    unsigned long TotalCaptured;    // 총 캡처된 패킷 수
    unsigned long TotalBlocked;     // 총 차단된 패킷 수
    unsigned long DroppedPackets;   // 큐 오버플로우로 드롭된 패킷 수
    // SNI 차단 통계
    unsigned long SniBlockingEnabled;   // SNI 차단 활성화 여부
    unsigned long SniBlockedUrls;       // 등록된 차단 URL 수
    unsigned long SniTotalBlocked;      // SNI/QUIC로 차단된 총 연결 수
} CAPTURE_STATUS, * PCAPTURE_STATUS;

// 확장 캡처 상태 조회 응답 구조체 
typedef struct _CAPTURE_STATUS_EX {
    // 기본 필드 (CAPTURE_STATUS와 동일)
    unsigned long IsCapturing;
    unsigned long BlockedPid;
    unsigned long QueuedPackets;
    unsigned long TotalCaptured;
    unsigned long TotalBlocked;
    unsigned long DroppedPackets;
    unsigned long SniBlockingEnabled;
    unsigned long SniBlockedUrls;
    unsigned long SniTotalBlocked;

    // 확장 필드 
    unsigned long QuicBlockingEnabled;  // QUIC 차단 활성화 여부
    unsigned long QuicTotalBlocked;     // QUIC으로만 차단된 연결 수
    unsigned long DnsMonitoringEnabled; // DNS 모니터링 활성화 여부
    unsigned long DnsBasedBlocked;      // DNS 기반 차단 연결 수
    unsigned long IpCacheCount;         // IP 캐시에 저장된 IP 수
    unsigned long IpCacheHits;          // IP 캐시 히트 수
    unsigned long Reserved[2];          // 향후 확장용
} CAPTURE_STATUS_EX, * PCAPTURE_STATUS_EX;

// 개별 패킷 메타데이터 구조체
typedef struct _PACKET_INFO {
    // 타임스탬프 (시스템 시간, 100ns 단위)
    unsigned __int64 Timestamp;

    // 프로세스 정보
    unsigned long ProcessId;

    // IP 주소 (IPv4, 네트워크 바이트 오더)
    unsigned long LocalAddress;
    unsigned long RemoteAddress;

    // 포트 (호스트 바이트 오더)
    unsigned short LocalPort;
    unsigned short RemotePort;

    // 프로토콜 (TCP=6, UDP=17, ICMP=1)
    unsigned char Protocol;

    // 패킷 방향 (PACKET_DIRECTION)
    unsigned char Direction;

    // 패킷 액션 (PACKET_ACTION)
    unsigned char Action;

    // 예약 (정렬용)
    unsigned char Reserved;

    // 패킷 크기 (바이트)
    unsigned long PacketSize;

    // 추가 패딩 (64비트 정렬)
    unsigned long Reserved2;

} PACKET_INFO, * PPACKET_INFO;

// 패킷 배치 컨테이너 구조체
typedef struct _PACKET_BATCH {
    // 이 배치에 포함된 패킷 수
    unsigned long PacketCount;

    // 큐에 남은 패킷 수 (추가 조회 필요 여부 판단용)
    unsigned long RemainingPackets;

    // 시퀀스 번호 (배치 순서용)
    unsigned long SequenceNumber;

    // 예약
    unsigned long Reserved;

    // 패킷 데이터 배열
    PACKET_INFO Packets[MAX_PACKETS_PER_BATCH];

} PACKET_BATCH, * PPACKET_BATCH;

// ============================================================================
// SNI 차단 관련 구조체
// ============================================================================

// SNI URL 차단 요청 구조체
typedef struct _SNI_BLOCK_REQUEST {
    char Url[MAX_SNI_LENGTH];       // 차단할 URL (null-terminated)
    unsigned long Action;           // 0: 자동(토글), 1: 추가, 2: 제거
    unsigned long Reserved;         // 정렬용 패딩
} SNI_BLOCK_REQUEST, * PSNI_BLOCK_REQUEST;

// SNI 차단 요청 액션 상수
#define SNI_ACTION_TOGGLE   0   // 토글 (있으면 제거, 없으면 추가)
#define SNI_ACTION_ADD      1   // 추가
#define SNI_ACTION_REMOVE   2   // 제거

// SNI 차단 응답 구조체
typedef struct _SNI_BLOCK_RESPONSE {
    unsigned long Success;          // 성공 여부
    unsigned long IsBlocked;        // 현재 차단 상태 (1: 차단 중, 0: 차단 해제됨)
    unsigned long TotalBlockedUrls; // 전체 차단 URL 수
    unsigned long Reserved;         // 정렬용 패딩
} SNI_BLOCK_RESPONSE, * PSNI_BLOCK_RESPONSE;

// SNI 차단 리스트 조회 요청
typedef struct _SNI_LIST_REQUEST {
    unsigned long StartIndex;       // 시작 인덱스
    unsigned long MaxCount;         // 최대 반환 개수
} SNI_LIST_REQUEST, * PSNI_LIST_REQUEST;

// SNI 차단 URL 엔트리
typedef struct _SNI_URL_ENTRY {
    char Url[MAX_SNI_LENGTH];       // URL
    unsigned long BlockCount;       // 차단 횟수
    unsigned long Reserved;         // 정렬용 패딩
} SNI_URL_ENTRY, * PSNI_URL_ENTRY;

// SNI 차단 리스트 응답 구조체
typedef struct _SNI_LIST_RESPONSE {
    unsigned long TotalCount;       // 전체 차단 URL 수
    unsigned long ReturnedCount;    // 이 응답에 포함된 URL 수
    unsigned long StartIndex;       // 시작 인덱스
    unsigned long HasMore;          // 더 많은 항목 존재 여부 (v3.0: Reserved -> HasMore)
    SNI_URL_ENTRY Entries[SNI_BLOCK_LIST_SIZE]; // URL 엔트리 배열
} SNI_LIST_RESPONSE, * PSNI_LIST_RESPONSE;

// SNI 차단 토글 구조체
typedef struct _SNI_TOGGLE {
    unsigned long Enable;           // 0: 비활성화, 1: 활성화
    unsigned long Reserved;         // 정렬용 패딩
} SNI_TOGGLE, * PSNI_TOGGLE;

// ============================================================================
// IP 캐시 관련 구조체 
// ============================================================================

// IP 캐시 엔트리 (조회용)
typedef struct _IP_CACHE_ENTRY {
    unsigned long IpAddress;        // IP 주소 (네트워크 바이트 오더)
    char AssociatedSni[MAX_SNI_LENGTH]; // 연결된 SNI
    unsigned long HitCount;         // 히트 횟수
    unsigned long AgeSeconds;       // 캐시에 저장된 시간 (초)
} IP_CACHE_ENTRY, * PIP_CACHE_ENTRY;

// IP 캐시 상태 조회 응답
typedef struct _IP_CACHE_STATUS {
    unsigned long TotalEntries;     // 전체 엔트리 수
    unsigned long MaxEntries;       // 최대 엔트리 수
    unsigned long TimeoutSeconds;   // 만료 시간 (초)
    unsigned long Reserved;
} IP_CACHE_STATUS, * PIP_CACHE_STATUS;

// ============================================================================
// DNS Sinkhole 관련 구조체 (v3.0 신규)
// ============================================================================

// DNS 싱크홀 토글 구조체
typedef struct _DNS_SINKHOLE_TOGGLE {
    unsigned long Enable;           // 0: 비활성화, 1: 활성화
    unsigned long Reserved;         // 정렬용 패딩
} DNS_SINKHOLE_TOGGLE, * PDNS_SINKHOLE_TOGGLE;

// DNS 싱크홀 설정 구조체
typedef struct _DNS_SINKHOLE_CONFIG {
    unsigned long SinkholeIp;       // 싱크홀 IP (호스트 바이트 오더, 기본값: 127.0.0.1)
    unsigned short HttpPort;        // HTTP 포트 (기본값: 80)
    unsigned short HttpsPort;       // HTTPS 포트 (기본값: 443)
    unsigned long Reserved;         // 정렬용 패딩
} DNS_SINKHOLE_CONFIG, * PDNS_SINKHOLE_CONFIG;

// DNS 싱크홀 상태 조회 응답 구조체
typedef struct _DNS_SINKHOLE_STATUS {
    unsigned long Enabled;              // 활성화 상태
    unsigned long SinkholeIp;           // 현재 싱크홀 IP
    unsigned short HttpPort;            // 현재 HTTP 포트
    unsigned short HttpsPort;           // 현재 HTTPS 포트
    unsigned long long TotalRedirected; // 총 리다이렉션된 연결 수
    unsigned long long TotalDnsModified;// 총 수정된 DNS 응답 수
    unsigned long Reserved[2];          // 향후 확장용
} DNS_SINKHOLE_STATUS, * PDNS_SINKHOLE_STATUS;

#pragma pack(pop)

// ============================================================================
// 유틸리티 매크로
// ============================================================================

// IP 주소를 바이트 배열로 분리 (네트워크 바이트 오더 기준)
#define IP_BYTE1(ip) (((ip) >> 24) & 0xFF)
#define IP_BYTE2(ip) (((ip) >> 16) & 0xFF)
#define IP_BYTE3(ip) (((ip) >> 8) & 0xFF)
#define IP_BYTE4(ip) (((ip) >> 0) & 0xFF)

// IP 주소 출력 포맷 매크로
#define IP_FORMAT "%u.%u.%u.%u"
#define IP_ARGS(ip) IP_BYTE1(ip), IP_BYTE2(ip), IP_BYTE3(ip), IP_BYTE4(ip)

// 프로토콜 문자열 변환
#define PROTO_TO_STR(p) \
    ((p) == PROTO_TCP ? "TCP" : \
     (p) == PROTO_UDP ? "UDP" : \
     (p) == PROTO_ICMP ? "ICMP" : "OTHER")

// 방향 문자열 변환 
#define DIR_TO_STR(d) \
    ((d) == PACKET_DIR_OUTBOUND ? "OUT" : "IN")

// 액션 문자열 변환 
#define ACTION_TO_STR(a) \
    ((a) == PACKET_ACTION_PERMIT ? "PERMIT" : "BLOCK")

// QUIC 패킷 타입 확인 매크로 
#define IS_QUIC_LONG_HEADER(byte) (((byte) & QUIC_LONG_HEADER_MASK) != 0)
#define GET_QUIC_PACKET_TYPE(byte) (((byte) >> 4) & 0x03)

// ============================================================================
// 구조체 크기 검증 (컴파일 타임) - User Mode C++에서만
// ============================================================================
#ifndef __KERNEL_MODE__
#ifdef __cplusplus
static_assert(sizeof(PACKET_INFO) == 40, "PACKET_INFO size mismatch");
static_assert(sizeof(PACKET_BATCH) == 16 + (40 * MAX_PACKETS_PER_BATCH), "PACKET_BATCH size mismatch");
static_assert(sizeof(SNI_BLOCK_REQUEST) == MAX_SNI_LENGTH + 8, "SNI_BLOCK_REQUEST size mismatch");
static_assert(sizeof(SNI_URL_ENTRY) == MAX_SNI_LENGTH + 8, "SNI_URL_ENTRY size mismatch");
static_assert(sizeof(CAPTURE_STATUS) == 36, "CAPTURE_STATUS size mismatch");
static_assert(sizeof(CAPTURE_STATUS_EX) == 68, "CAPTURE_STATUS_EX size mismatch");
static_assert(sizeof(DNS_SINKHOLE_TOGGLE) == 8, "DNS_SINKHOLE_TOGGLE size mismatch");
static_assert(sizeof(DNS_SINKHOLE_CONFIG) == 12, "DNS_SINKHOLE_CONFIG size mismatch");
static_assert(sizeof(DNS_SINKHOLE_STATUS) == 40, "DNS_SINKHOLE_STATUS size mismatch");
#endif
#endif

// ============================================================================
// 버전 정보 
// ============================================================================
#define WFP_FILTER_VERSION_MAJOR    3
#define WFP_FILTER_VERSION_MINOR    0
#define WFP_FILTER_VERSION_STRING   "3.0"
