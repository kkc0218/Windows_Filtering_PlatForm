#pragma once

// ============================================================================
// Shared.h - WFP Packet Filtering & Capture System Common Header
// ============================================================================
// 이 헤더는 User Mode 응용프로그램과 Kernel Mode 드라이버 간의
// 인터페이스를 정의합니다. 32/64비트 호환성을 보장합니다.
// ============================================================================

#include <devioctl.h>
#include <guiddef.h>

// ============================================================================
// 디바이스 이름 정의
// ============================================================================
#define DEVICE_NAME         L"\\Device\\WfpExampleDevice"
#define SYMBOLIC_LINK_NAME  L"\\??\\WfpExampleLink"

// ============================================================================
// GUID 정의 - WFP Callout 식별자
// {B180900E-B939-4E64-912A-63799634B03B}
// ============================================================================
#ifndef GUID_MY_WFP_CALLOUT_DEFINED
#define GUID_MY_WFP_CALLOUT_DEFINED
DEFINE_GUID(GUID_MY_WFP_CALLOUT,
    0xb180900e, 0xb939, 0x4e64, 0x91, 0x2a, 0x63, 0x79, 0x96, 0x34, 0xb0, 0x3b);
#endif

// ============================================================================
// IOCTL 코드 정의
// ============================================================================
// 기존 PID 차단 설정
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
// 상수 정의
// ============================================================================
#define MAX_PACKETS_PER_BATCH   64      // 배치당 최대 패킷 수
#define PACKET_QUEUE_SIZE       256     // 드라이버 내부 큐 크기 (링 버퍼)

// ============================================================================
// 프로토콜 상수 (IPPROTO_*)
// ============================================================================
#define PROTO_ICMP      1
#define PROTO_TCP       6
#define PROTO_UDP       17

// ============================================================================
// 패킷 방향 정의
// ============================================================================
typedef enum _PACKET_DIRECTION {
    PACKET_DIR_OUTBOUND = 0,    // 송신 패킷
    PACKET_DIR_INBOUND = 1     // 수신 패킷
} PACKET_DIRECTION;

// ============================================================================
// 패킷 액션 정의
// ============================================================================
typedef enum _PACKET_ACTION {
    PACKET_ACTION_PERMIT = 0,   // 허용됨
    PACKET_ACTION_BLOCK = 1    // 차단됨
} PACKET_ACTION;

// ============================================================================
// 데이터 구조체 정의
// ============================================================================

#pragma pack(push, 8)  // 8바이트 정렬로 32/64비트 호환성 보장

// 기존 PID 차단 설정 구조체
typedef struct _BLOCK_CONFIG {
    unsigned long ProcessId;
    unsigned long Reserved;     // 정렬용 패딩
} BLOCK_CONFIG, * PBLOCK_CONFIG;

// 캡처 토글 설정 구조체
typedef struct _CAPTURE_TOGGLE {
    unsigned long Enable;       // 0: 비활성화, 1: 활성화
    unsigned long Reserved;     // 정렬용 패딩
} CAPTURE_TOGGLE, * PCAPTURE_TOGGLE;

// 캡처 상태 조회 응답 구조체
typedef struct _CAPTURE_STATUS {
    unsigned long IsCapturing;      // 현재 캡처 상태
    unsigned long BlockedPid;       // 현재 차단 중인 PID
    unsigned long QueuedPackets;    // 큐에 대기 중인 패킷 수
    unsigned long TotalCaptured;    // 총 캡처된 패킷 수
    unsigned long TotalBlocked;     // 총 차단된 패킷 수
    unsigned long DroppedPackets;   // 큐 오버플로우로 드롭된 패킷 수
} CAPTURE_STATUS, * PCAPTURE_STATUS;

// 단일 패킷 메타데이터 구조체
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

    // 시퀀스 번호 (배치 추적용)
    unsigned long SequenceNumber;

    // 예약
    unsigned long Reserved;

    // 패킷 데이터 배열
    PACKET_INFO Packets[MAX_PACKETS_PER_BATCH];

} PACKET_BATCH, * PPACKET_BATCH;

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

// ============================================================================
// 구조체 크기 검증 (컴파일 타임)
// ============================================================================
#ifndef __KERNEL_MODE__
// User Mode에서만 static_assert 사용
#ifdef __cplusplus
static_assert(sizeof(PACKET_INFO) == 40, "PACKET_INFO size mismatch");
static_assert(sizeof(PACKET_BATCH) == 16 + (40 * MAX_PACKETS_PER_BATCH), "PACKET_BATCH size mismatch");
#endif
#endif
