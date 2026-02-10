// ============================================================================
// sample_fixed.c - WFP Packet Filtering & Capture Kernel Driver 
// ============================================================================

#include <ntddk.h>
#include <ndis.h>

#pragma warning(push)
#pragma warning(disable: 4201)
#include <initguid.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <ntstrsafe.h>
#pragma warning(pop)

#define __KERNEL_MODE__
#include "Shared.h"

#pragma comment(lib, "fwpkclnt.lib")
#pragma comment(lib, "ndis.lib")

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS RegisterWfpFilter(_In_ PDEVICE_OBJECT pDeviceObj);
void UnregisterWfpFilter(void);

// 콜백 함수 선언
void NTAPI FilterClassifyConnect(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI FilterNotifyConnect(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter
);

void NTAPI FilterClassifyStream(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI FilterNotifyStream(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter
);

void NTAPI FilterClassifyQuic(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI FilterNotifyQuic(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter
);

// DNS 모니터링 콜백 (신규)
void NTAPI FilterClassifyDns(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI FilterNotifyDns(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter
);

// SNI 차단 관련 전방 선언 (버그 수정: IsIpBlockedWithSniIncrement에서 사용)
BOOLEAN IsSniBlocked(_In_ const CHAR* sni);

// ============================================================================
// 메모리 섹션 설정
// ============================================================================
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, DispatchCreateClose)
#pragma alloc_text(PAGE, DispatchDeviceControl)
#pragma alloc_text(PAGE, RegisterWfpFilter)
#pragma alloc_text(PAGE, UnregisterWfpFilter)
#endif

// ============================================================================
// IP 캐시 구조체 - 개선됨
// ============================================================================
typedef struct _BLOCKED_IP_ENTRY {
    ULONG IpAddress;
    CHAR AssociatedSni[MAX_SNI_LENGTH];
    LARGE_INTEGER AddedTime;
    volatile LONG HitCount;     // 히트 카운트 추가 (자주 사용되는 IP 우선 유지)
    BOOLEAN InUse;
    UCHAR Reserved[3];
} BLOCKED_IP_ENTRY, * PBLOCKED_IP_ENTRY;

typedef struct _BLOCKED_IP_CACHE {
    BLOCKED_IP_ENTRY Entries[MAX_BLOCKED_IPS];
    volatile LONG Count;
    KSPIN_LOCK Lock;
} BLOCKED_IP_CACHE, * PBLOCKED_IP_CACHE;

// ============================================================================
// SNI 차단 리스트 구조체
// ============================================================================
typedef struct _SNI_BLOCK_ENTRY {
    CHAR Url[MAX_SNI_LENGTH];
    volatile LONG BlockCount;
    BOOLEAN InUse;
    UCHAR Reserved[3];
} SNI_BLOCK_ENTRY, * PSNI_BLOCK_ENTRY;

typedef struct _SNI_BLOCK_LIST {
    SNI_BLOCK_ENTRY Entries[MAX_BLOCKED_URLS];
    volatile LONG Count;
    KSPIN_LOCK Lock;
} SNI_BLOCK_LIST, * PSNI_BLOCK_LIST;

// ============================================================================
// 패킷 큐 구조체
// ============================================================================
typedef struct _PACKET_QUEUE_ENTRY {
    PACKET_INFO Info;
} PACKET_QUEUE_ENTRY, * PPACKET_QUEUE_ENTRY;

typedef struct _PACKET_RING_BUFFER {
    PACKET_QUEUE_ENTRY Entries[PACKET_QUEUE_SIZE];
    volatile LONG Head;
    volatile LONG Tail;
    volatile LONG Count;
    KSPIN_LOCK Lock;
} PACKET_RING_BUFFER, * PPACKET_RING_BUFFER;

// ============================================================================
// 드라이버 컨텍스트 구조체
// ============================================================================
typedef struct _DRIVER_CONTEXT {
    HANDLE EngineHandle;

    // Callout IDs
    UINT32 CalloutIdConnect;
    UINT64 FilterIdConnect;
    UINT32 CalloutIdStream;
    UINT64 FilterIdStream;
    UINT32 CalloutIdQuic;
    UINT64 FilterIdQuic;
    UINT32 CalloutIdDns;        // DNS 콜아웃 (신규)
    UINT64 FilterIdDns;

    // 설정
    volatile ULONG BlockedPid;
    volatile ULONG CaptureEnabled;
    volatile ULONG SniBlockingEnabled;
    volatile ULONG QuicBlockingEnabled;
    volatile ULONG DnsMonitoringEnabled;    // DNS 모니터링 (신규)

    // 통계
    volatile LONG64 TotalCaptured;
    volatile LONG64 TotalBlocked;
    volatile LONG64 DroppedPackets;
    volatile LONG64 SniTotalBlocked;
    volatile LONG64 QuicTotalBlocked;
    volatile LONG64 DnsBlocked;             // DNS 기반 차단 (신규)

    // 데이터 구조
    PPACKET_RING_BUFFER PacketQueue;
    PSNI_BLOCK_LIST SniBlockList;
    PBLOCKED_IP_CACHE IpCache;

    volatile LONG BatchSequence;

    // ============================================================================
    // DNS 싱크홀 컨텍스트 
    // ============================================================================
    volatile ULONG DnsSinkholeEnabled;      // DNS 싱크홀 활성화 상태
    volatile ULONG SinkholeIp;              // 싱크홀 IP (호스트 바이트 오더)
    volatile USHORT SinkholeHttpPort;       // HTTP 포트
    volatile USHORT SinkholeHttpsPort;      // HTTPS 포트
    volatile LONG64 TotalDnsModified;       // 수정된 DNS 응답 수
    volatile LONG64 TotalSinkholeRedirected;// 싱크홀로 리다이렉션된 연결 수
    KSPIN_LOCK DnsSinkholeLock;             // 싱크홀 설정 보호용 스핀락
} DRIVER_CONTEXT, * PDRIVER_CONTEXT;

// ============================================================================
// 전역 변수
// ============================================================================
static PDRIVER_CONTEXT g_DriverContext = NULL;
static PDEVICE_OBJECT g_DeviceObject = NULL;

// ============================================================================
// 유틸리티 함수
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
void ToLowerCase(_Inout_ CHAR* str, _In_ SIZE_T maxLen)
{
    for (SIZE_T i = 0; i < maxLen && str[i] != '\0'; i++) {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] = str[i] + ('a' - 'A');
        }
    }
}

// 루프백 주소 확인 (127.0.0.0/8) - 싱크홀 서버 연결 허용용
// WFP의 IP 주소는 호스트 바이트 오더 (Windows = 리틀엔디안)
// 127.x.x.x 체크
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN IsLoopbackAddress(_In_ UINT32 hostOrderIp)
{
    // 호스트 바이트 오더에서 첫 번째 옥텟 추출
    UCHAR firstByte = (UCHAR)((hostOrderIp >> 24) & 0xFF);
    return (firstByte == 127);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(output != NULL && maxLen > 0)
void NormalizeUrl(
    _In_opt_ const CHAR* input,
    _Out_writes_z_(maxLen) CHAR* output,
    _In_ SIZE_T maxLen)
{
    // 무조건 초기화 (분석기 경고 해결)
    if (output == NULL || maxLen == 0) {
        return;
    }
    output[0] = '\0';

    if (input == NULL) {
        return;
    }

    const CHAR* src = input;

    // 스키마 제거
    if (_strnicmp(src, "https://", 8) == 0) {
        src += 8;
    }
    else if (_strnicmp(src, "http://", 7) == 0) {
        src += 7;
    }

    // www. 제거
    if (_strnicmp(src, "www.", 4) == 0) {
        src += 4;
    }

    // 도메인만 복사 (경로, 포트 제외)
    SIZE_T i = 0;
    for (; i < maxLen - 1 && src[i] != '\0' && src[i] != '/' && src[i] != ':'; i++) {
        output[i] = src[i];
    }
    output[i] = '\0';

    ToLowerCase(output, maxLen);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64 GetCurrentTimestamp(void)
{
    LARGE_INTEGER systemTime;
    LARGE_INTEGER localTime;
    KeQuerySystemTime(&systemTime);
    ExSystemTimeToLocalTime(&systemTime, &localTime);
    return (UINT64)localTime.QuadPart;
}

// ============================================================================
// IP 캐시 함수 (개선됨)
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS InitializeIpCache(void)
{
    if (g_DriverContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    g_DriverContext->IpCache = (PBLOCKED_IP_CACHE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(BLOCKED_IP_CACHE),
        'CIFW'
    );

    if (g_DriverContext->IpCache == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_DriverContext->IpCache, sizeof(BLOCKED_IP_CACHE));
    KeInitializeSpinLock(&g_DriverContext->IpCache->Lock);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
void CleanupIpCache(void)
{
    if (g_DriverContext != NULL && g_DriverContext->IpCache != NULL) {
        ExFreePoolWithTag(g_DriverContext->IpCache, 'CIFW');
        g_DriverContext->IpCache = NULL;
    }
}

// IP 캐시에 추가 (개선: LRU 방식으로 공간 확보)
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN AddBlockedIp(_In_ ULONG ipAddress, _In_ const CHAR* sni)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PBLOCKED_IP_CACHE cache;
    BOOLEAN result = FALSE;
    LARGE_INTEGER currentTime;
    LONG oldestIndex = -1;
    LARGE_INTEGER oldestTime = { 0 };

    if (g_DriverContext == NULL || g_DriverContext->IpCache == NULL || ipAddress == 0) {
        return FALSE;
    }

    // 루프백 주소(127.0.0.0/8)는 캐시에 추가하지 않음 (싱크홀 서버 보호)
    if (IsLoopbackAddress(ipAddress)) {
        return FALSE;
    }

    cache = g_DriverContext->IpCache;
    KeQuerySystemTime(&currentTime);
    oldestTime.QuadPart = currentTime.QuadPart;

    KeAcquireInStackQueuedSpinLock(&cache->Lock, &lockHandle);

    // 이미 존재하는지 확인
    for (LONG i = 0; i < MAX_BLOCKED_IPS; i++) {
        if (cache->Entries[i].InUse) {
            if (cache->Entries[i].IpAddress == ipAddress) {
                // 이미 존재하면 시간과 히트 카운트 갱신
                cache->Entries[i].AddedTime = currentTime;
                InterlockedIncrement(&cache->Entries[i].HitCount);
                KeReleaseInStackQueuedSpinLock(&lockHandle);
                return TRUE;
            }
            // 가장 오래된 엔트리 추적 (LRU용)
            if (cache->Entries[i].AddedTime.QuadPart < oldestTime.QuadPart) {
                oldestTime = cache->Entries[i].AddedTime;
                oldestIndex = i;
            }
        }
    }

    // 빈 슬롯 찾기
    for (LONG i = 0; i < MAX_BLOCKED_IPS; i++) {
        if (!cache->Entries[i].InUse) {
            cache->Entries[i].IpAddress = ipAddress;
            cache->Entries[i].AddedTime = currentTime;
            cache->Entries[i].HitCount = 1;
            cache->Entries[i].InUse = TRUE;
            if (sni != NULL) {
                RtlStringCchCopyA(cache->Entries[i].AssociatedSni, MAX_SNI_LENGTH, sni);
            }
            else {
                cache->Entries[i].AssociatedSni[0] = '\0';
            }
            InterlockedIncrement(&cache->Count);
            result = TRUE;
            KdPrint(("WFP IP Cache: Added IP %u.%u.%u.%u for SNI %s\n",
                (ipAddress >> 24) & 0xFF, (ipAddress >> 16) & 0xFF,
                (ipAddress >> 8) & 0xFF, ipAddress & 0xFF,
                sni ? sni : "(none)"));
            break;
        }
    }

    // 빈 슬롯이 없으면 가장 오래된 엔트리 교체 (LRU)
    if (!result && oldestIndex >= 0) {
        cache->Entries[oldestIndex].IpAddress = ipAddress;
        cache->Entries[oldestIndex].AddedTime = currentTime;
        cache->Entries[oldestIndex].HitCount = 1;
        if (sni != NULL) {
            RtlStringCchCopyA(cache->Entries[oldestIndex].AssociatedSni, MAX_SNI_LENGTH, sni);
        }
        else {
            cache->Entries[oldestIndex].AssociatedSni[0] = '\0';
        }
        result = TRUE;
        KdPrint(("WFP IP Cache: Replaced oldest entry with IP %u.%u.%u.%u\n",
            (ipAddress >> 24) & 0xFF, (ipAddress >> 16) & 0xFF,
            (ipAddress >> 8) & 0xFF, ipAddress & 0xFF));
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return result;
}

// IP가 차단 목록에 있는지 확인
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN IsIpBlocked(_In_ ULONG ipAddress)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PBLOCKED_IP_CACHE cache;
    BOOLEAN blocked = FALSE;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER timeout;

    if (g_DriverContext == NULL || g_DriverContext->IpCache == NULL ||
        g_DriverContext->SniBlockingEnabled == 0 || ipAddress == 0) {
        return FALSE;
    }

    cache = g_DriverContext->IpCache;
    KeQuerySystemTime(&currentTime);

    // 타임아웃 계산 (30분)
    timeout.QuadPart = (LONGLONG)IP_CACHE_TIMEOUT_SEC * 10000000LL;

    KeAcquireInStackQueuedSpinLock(&cache->Lock, &lockHandle);

    for (LONG i = 0; i < MAX_BLOCKED_IPS; i++) {
        if (cache->Entries[i].InUse) {
            // 만료 확인
            if ((currentTime.QuadPart - cache->Entries[i].AddedTime.QuadPart) > timeout.QuadPart) {
                cache->Entries[i].InUse = FALSE;
                cache->Entries[i].IpAddress = 0;
                InterlockedDecrement(&cache->Count);
                continue;
            }

            if (cache->Entries[i].IpAddress == ipAddress) {
                blocked = TRUE;
                InterlockedIncrement(&cache->Entries[i].HitCount);
                // 히트 시 시간 갱신 (자주 사용되는 IP는 더 오래 유지)
                cache->Entries[i].AddedTime = currentTime;
                break;
            }
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return blocked;
}

// IP가 차단 목록에 있는지 확인하고 연관된 SNI의 차단 횟수도 증가시킴 (버그 수정)
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN IsIpBlockedWithSniIncrement(_In_ ULONG ipAddress)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PBLOCKED_IP_CACHE cache;
    BOOLEAN blocked = FALSE;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER timeout;
    CHAR associatedSni[MAX_SNI_LENGTH];

    associatedSni[0] = '\0';

    if (g_DriverContext == NULL || g_DriverContext->IpCache == NULL ||
        g_DriverContext->SniBlockingEnabled == 0 || ipAddress == 0) {
        return FALSE;
    }

    cache = g_DriverContext->IpCache;
    KeQuerySystemTime(&currentTime);

    // 타임아웃 계산 (30분)
    timeout.QuadPart = (LONGLONG)IP_CACHE_TIMEOUT_SEC * 10000000LL;

    KeAcquireInStackQueuedSpinLock(&cache->Lock, &lockHandle);

    for (LONG i = 0; i < MAX_BLOCKED_IPS; i++) {
        if (cache->Entries[i].InUse) {
            // 만료 확인
            if ((currentTime.QuadPart - cache->Entries[i].AddedTime.QuadPart) > timeout.QuadPart) {
                cache->Entries[i].InUse = FALSE;
                cache->Entries[i].IpAddress = 0;
                InterlockedDecrement(&cache->Count);
                continue;
            }

            if (cache->Entries[i].IpAddress == ipAddress) {
                blocked = TRUE;
                InterlockedIncrement(&cache->Entries[i].HitCount);
                cache->Entries[i].AddedTime = currentTime;
                // 연관된 SNI 복사
                if (cache->Entries[i].AssociatedSni[0] != '\0') {
                    RtlStringCchCopyA(associatedSni, MAX_SNI_LENGTH, cache->Entries[i].AssociatedSni);
                }
                break;
            }
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    // IP 캐시 기반 차단 시 연관된 SNI의 차단 횟수도 증가시킴 (버그 수정)
    if (blocked && associatedSni[0] != '\0') {
        IsSniBlocked(associatedSni);
    }

    return blocked;
}

// SNI에 연관된 IP 제거
_IRQL_requires_max_(DISPATCH_LEVEL)
void RemoveIpsForSni(_In_ const CHAR* sni)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PBLOCKED_IP_CACHE cache;
    CHAR normalizedSni[MAX_SNI_LENGTH];

    if (g_DriverContext == NULL || g_DriverContext->IpCache == NULL || sni == NULL) {
        return;
    }

    cache = g_DriverContext->IpCache;
    NormalizeUrl(sni, normalizedSni, MAX_SNI_LENGTH);

    KeAcquireInStackQueuedSpinLock(&cache->Lock, &lockHandle);

    for (LONG i = 0; i < MAX_BLOCKED_IPS; i++) {
        if (cache->Entries[i].InUse) {
            if (_stricmp(cache->Entries[i].AssociatedSni, normalizedSni) == 0) {
                RtlZeroMemory(&cache->Entries[i], sizeof(BLOCKED_IP_ENTRY));
                InterlockedDecrement(&cache->Count);
            }
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

// ============================================================================
// SNI 차단 리스트 함수
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS InitializeSniBlockList(void)
{
    if (g_DriverContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    g_DriverContext->SniBlockList = (PSNI_BLOCK_LIST)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SNI_BLOCK_LIST),
        'LSNW'
    );

    if (g_DriverContext->SniBlockList == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_DriverContext->SniBlockList, sizeof(SNI_BLOCK_LIST));
    KeInitializeSpinLock(&g_DriverContext->SniBlockList->Lock);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
void CleanupSniBlockList(void)
{
    if (g_DriverContext != NULL && g_DriverContext->SniBlockList != NULL) {
        ExFreePoolWithTag(g_DriverContext->SniBlockList, 'LSNW');
        g_DriverContext->SniBlockList = NULL;
    }
}

// SNI 차단 리스트에 URL 추가
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN AddSniUrl(_In_ const CHAR* url)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    CHAR normalizedUrl[MAX_SNI_LENGTH];
    PSNI_BLOCK_LIST list;
    BOOLEAN result = FALSE;

    if (g_DriverContext == NULL || g_DriverContext->SniBlockList == NULL || url == NULL) {
        return FALSE;
    }

    list = g_DriverContext->SniBlockList;
    NormalizeUrl(url, normalizedUrl, MAX_SNI_LENGTH);

    if (normalizedUrl[0] == '\0') {
        return FALSE;
    }

    KeAcquireInStackQueuedSpinLock(&list->Lock, &lockHandle);

    // 이미 존재하는지 확인
    for (LONG i = 0; i < MAX_BLOCKED_URLS; i++) {
        if (list->Entries[i].InUse && _stricmp(list->Entries[i].Url, normalizedUrl) == 0) {
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            return FALSE;  // 이미 존재
        }
    }

    // 빈 슬롯 찾기
    for (LONG i = 0; i < MAX_BLOCKED_URLS; i++) {
        if (!list->Entries[i].InUse) {
            RtlZeroMemory(&list->Entries[i], sizeof(SNI_BLOCK_ENTRY));
            RtlStringCchCopyA(list->Entries[i].Url, MAX_SNI_LENGTH, normalizedUrl);
            list->Entries[i].BlockCount = 0;
            list->Entries[i].InUse = TRUE;
            InterlockedIncrement(&list->Count);
            result = TRUE;
            KdPrint(("WFP SNI: Added URL to block list: %s (index=%d, total=%d)\n",
                normalizedUrl, i, list->Count));
            break;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return result;
}

// SNI 차단 리스트에서 URL 제거
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN RemoveSniUrl(_In_ const CHAR* url)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    CHAR normalizedUrl[MAX_SNI_LENGTH];
    PSNI_BLOCK_LIST list;
    BOOLEAN result = FALSE;

    if (g_DriverContext == NULL || g_DriverContext->SniBlockList == NULL || url == NULL) {
        return FALSE;
    }

    list = g_DriverContext->SniBlockList;
    NormalizeUrl(url, normalizedUrl, MAX_SNI_LENGTH);

    KeAcquireInStackQueuedSpinLock(&list->Lock, &lockHandle);

    for (LONG i = 0; i < MAX_BLOCKED_URLS; i++) {
        if (list->Entries[i].InUse && _stricmp(list->Entries[i].Url, normalizedUrl) == 0) {
            // 연관 IP도 제거
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            RemoveIpsForSni(list->Entries[i].Url);
            KeAcquireInStackQueuedSpinLock(&list->Lock, &lockHandle);

            RtlZeroMemory(&list->Entries[i], sizeof(SNI_BLOCK_ENTRY));
            InterlockedDecrement(&list->Count);
            result = TRUE;
            KdPrint(("WFP SNI: Removed URL from block list: %s\n", normalizedUrl));
            break;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return result;
}

// SNI URL 토글
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN ToggleSniUrl(_In_ const CHAR* url, _Out_ BOOLEAN* isNowBlocked)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    CHAR normalizedUrl[MAX_SNI_LENGTH];
    PSNI_BLOCK_LIST list;
    BOOLEAN result = FALSE;
    LONG existingIndex = -1;

    if (isNowBlocked != NULL) {
        *isNowBlocked = FALSE;
    }

    if (g_DriverContext == NULL || g_DriverContext->SniBlockList == NULL ||
        url == NULL || isNowBlocked == NULL) {
        return FALSE;
    }

    list = g_DriverContext->SniBlockList;
    NormalizeUrl(url, normalizedUrl, MAX_SNI_LENGTH);

    if (normalizedUrl[0] == '\0') {
        return FALSE;
    }

    KeAcquireInStackQueuedSpinLock(&list->Lock, &lockHandle);

    // 존재 여부 확인
    for (LONG i = 0; i < MAX_BLOCKED_URLS; i++) {
        if (list->Entries[i].InUse && _stricmp(list->Entries[i].Url, normalizedUrl) == 0) {
            existingIndex = i;
            break;
        }
    }

    if (existingIndex >= 0) {
        // 존재하면 삭제
        CHAR tempUrl[MAX_SNI_LENGTH];
        RtlStringCchCopyA(tempUrl, MAX_SNI_LENGTH, list->Entries[existingIndex].Url);
        RtlZeroMemory(&list->Entries[existingIndex], sizeof(SNI_BLOCK_ENTRY));
        InterlockedDecrement(&list->Count);
        *isNowBlocked = FALSE;
        result = TRUE;

        KeReleaseInStackQueuedSpinLock(&lockHandle);
        RemoveIpsForSni(tempUrl);  // 락 해제 후 IP 제거
        KdPrint(("WFP SNI: Toggled OFF: %s\n", normalizedUrl));
    }
    else {
        // 존재하지 않으면 추가
        for (LONG i = 0; i < MAX_BLOCKED_URLS; i++) {
            if (!list->Entries[i].InUse) {
                RtlZeroMemory(&list->Entries[i], sizeof(SNI_BLOCK_ENTRY));
                RtlStringCchCopyA(list->Entries[i].Url, MAX_SNI_LENGTH, normalizedUrl);
                list->Entries[i].BlockCount = 0;
                list->Entries[i].InUse = TRUE;
                InterlockedIncrement(&list->Count);
                *isNowBlocked = TRUE;
                result = TRUE;
                KdPrint(("WFP SNI: Toggled ON: %s (index=%d)\n", normalizedUrl, i));
                break;
            }
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);
    }

    return result;
}

// SNI가 차단 리스트에 있는지 확인 (개선: 와일드카드 매칭)
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN IsSniBlocked(_In_ const CHAR* sni)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    CHAR normalizedSni[MAX_SNI_LENGTH];
    PSNI_BLOCK_LIST list;
    BOOLEAN blocked = FALSE;

    if (g_DriverContext == NULL || g_DriverContext->SniBlockList == NULL ||
        sni == NULL || g_DriverContext->SniBlockingEnabled == 0) {
        return FALSE;
    }

    list = g_DriverContext->SniBlockList;
    NormalizeUrl(sni, normalizedSni, MAX_SNI_LENGTH);

    if (normalizedSni[0] == '\0') {
        return FALSE;
    }

    KeAcquireInStackQueuedSpinLock(&list->Lock, &lockHandle);

    for (LONG i = 0; i < MAX_BLOCKED_URLS; i++) {
        if (list->Entries[i].InUse && list->Entries[i].Url[0] != '\0') {
            SIZE_T blockLen = strlen(list->Entries[i].Url);
            SIZE_T sniLen = strlen(normalizedSni);

            // 정확한 매칭
            if (_stricmp(list->Entries[i].Url, normalizedSni) == 0) {
                InterlockedIncrement(&list->Entries[i].BlockCount);
                blocked = TRUE;
                KdPrint(("WFP SNI: Exact match blocked: %s (count=%d)\n",
                    normalizedSni, list->Entries[i].BlockCount));
                break;
            }
            // 서브도메인 매칭 (예: mail.google.com은 google.com 규칙으로 차단)
            else if (sniLen > blockLen + 1) {
                const CHAR* suffix = normalizedSni + (sniLen - blockLen);
                if (normalizedSni[sniLen - blockLen - 1] == '.' &&
                    _stricmp(suffix, list->Entries[i].Url) == 0) {
                    InterlockedIncrement(&list->Entries[i].BlockCount);
                    blocked = TRUE;
                    KdPrint(("WFP SNI: Subdomain match blocked: %s (rule: %s, count=%d)\n",
                        normalizedSni, list->Entries[i].Url, list->Entries[i].BlockCount));
                    break;
                }
            }
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (blocked) {
        InterlockedIncrement64(&g_DriverContext->SniTotalBlocked);
    }

    return blocked;
}

// SNI URL이 차단 리스트에 있는지만 확인 (카운트 증가 없이)
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN IsSniInBlockList(_In_ const CHAR* sni)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    CHAR normalizedSni[MAX_SNI_LENGTH];
    PSNI_BLOCK_LIST list;
    BOOLEAN found = FALSE;

    if (g_DriverContext == NULL || g_DriverContext->SniBlockList == NULL || sni == NULL) {
        return FALSE;
    }

    list = g_DriverContext->SniBlockList;
    NormalizeUrl(sni, normalizedSni, MAX_SNI_LENGTH);

    if (normalizedSni[0] == '\0') {
        return FALSE;
    }

    KeAcquireInStackQueuedSpinLock(&list->Lock, &lockHandle);

    for (LONG i = 0; i < MAX_BLOCKED_URLS; i++) {
        if (list->Entries[i].InUse && list->Entries[i].Url[0] != '\0') {
            SIZE_T blockLen = strlen(list->Entries[i].Url);
            SIZE_T sniLen = strlen(normalizedSni);

            if (_stricmp(list->Entries[i].Url, normalizedSni) == 0) {
                found = TRUE;
                break;
            }
            else if (sniLen > blockLen + 1) {
                const CHAR* suffix = normalizedSni + (sniLen - blockLen);
                if (normalizedSni[sniLen - blockLen - 1] == '.' &&
                    _stricmp(suffix, list->Entries[i].Url) == 0) {
                    found = TRUE;
                    break;
                }
            }
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return found;
}

// SNI 차단 리스트 전체 초기화
_IRQL_requires_max_(DISPATCH_LEVEL)
void ClearSniBlockList(void)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PSNI_BLOCK_LIST list;

    if (g_DriverContext == NULL || g_DriverContext->SniBlockList == NULL) {
        return;
    }

    list = g_DriverContext->SniBlockList;

    KeAcquireInStackQueuedSpinLock(&list->Lock, &lockHandle);

    for (LONG i = 0; i < MAX_BLOCKED_URLS; i++) {
        RtlZeroMemory(&list->Entries[i], sizeof(SNI_BLOCK_ENTRY));
    }
    list->Count = 0;

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    // IP 캐시도 초기화
    if (g_DriverContext->IpCache != NULL) {
        KLOCK_QUEUE_HANDLE ipLockHandle;
        KeAcquireInStackQueuedSpinLock(&g_DriverContext->IpCache->Lock, &ipLockHandle);
        RtlZeroMemory(g_DriverContext->IpCache->Entries,
            sizeof(BLOCKED_IP_ENTRY) * MAX_BLOCKED_IPS);
        g_DriverContext->IpCache->Count = 0;
        KeReleaseInStackQueuedSpinLock(&ipLockHandle);
    }

    KdPrint(("WFP SNI: Block list and IP cache cleared\n"));
}

// ============================================================================
// TLS SNI 파싱 함수
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN ExtractSniFromTlsClientHello(
    _In_reads_bytes_(dataLen) const UCHAR * data,
    _In_ SIZE_T dataLen,
    _Out_writes_z_(sniBufferLen) CHAR * sniBuffer,
    _In_ SIZE_T sniBufferLen
)
{
    SIZE_T offset = 0;
    SIZE_T sessionIdLen;
    SIZE_T cipherSuitesLen;
    SIZE_T compressionLen;
    SIZE_T extensionsLen;

    // 무조건 초기화 (분석기 경고 해결)
    if (sniBuffer == NULL || sniBufferLen < 1) {
        return FALSE;
    }
    sniBuffer[0] = '\0';

    if (data == NULL || dataLen < 44) {
        return FALSE;
    }

    // TLS Record Header 확인 (0x16 = Handshake)
    if (data[0] != 0x16) {
        return FALSE;
    }

    // TLS 버전 확인 (최소 TLS 1.0)
    if (data[1] != 0x03 || data[2] > 0x04) {
        return FALSE;
    }

    // Record Length
    SIZE_T recordLen = ((SIZE_T)data[3] << 8) | data[4];
    if (dataLen < 5 + recordLen || recordLen < 4) {
        return FALSE;
    }

    offset = 5;

    // Handshake Type 확인 (0x01 = ClientHello)
    if (data[offset] != 0x01) {
        return FALSE;
    }

    // Handshake Length (24-bit)
    offset += 4;  // Skip type + length

    // Client Version
    offset += 2;

    // Random (32 bytes)
    offset += 32;

    if (offset >= dataLen) return FALSE;

    // Session ID Length
    sessionIdLen = data[offset];
    offset += 1 + sessionIdLen;

    if (offset + 2 > dataLen) return FALSE;

    // Cipher Suites Length
    cipherSuitesLen = ((SIZE_T)data[offset] << 8) | data[offset + 1];
    offset += 2 + cipherSuitesLen;

    if (offset + 1 > dataLen) return FALSE;

    // Compression Methods Length
    compressionLen = data[offset];
    offset += 1 + compressionLen;

    if (offset + 2 > dataLen) return FALSE;

    // Extensions Length
    extensionsLen = ((SIZE_T)data[offset] << 8) | data[offset + 1];
    offset += 2;

    SIZE_T extensionsEnd = offset + extensionsLen;
    if (extensionsEnd > dataLen) {
        extensionsEnd = dataLen;
    }

    // Parse Extensions
    while (offset + 4 <= extensionsEnd) {
        USHORT extType = ((USHORT)data[offset] << 8) | data[offset + 1];
        USHORT extLen = ((USHORT)data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + extLen > extensionsEnd) break;

        // SNI Extension (Type = 0x0000)
        if (extType == 0x0000 && extLen > 5) {
            SIZE_T sniOffset = offset;
            // SNI List Length (2 bytes)
            sniOffset += 2;

            if (sniOffset < dataLen && data[sniOffset] == 0x00) {  // hostname type
                sniOffset++;
                if (sniOffset + 2 <= dataLen) {
                    USHORT sniLen = ((USHORT)data[sniOffset] << 8) | data[sniOffset + 1];
                    sniOffset += 2;

                    if (sniLen > 0 && sniLen < sniBufferLen - 1 &&
                        sniOffset + sniLen <= dataLen) {
                        RtlCopyMemory(sniBuffer, &data[sniOffset], sniLen);
                        sniBuffer[sniLen] = '\0';
                        ToLowerCase(sniBuffer, sniBufferLen);
                        KdPrint(("WFP TLS: Extracted SNI: %s\n", sniBuffer));
                        return TRUE;
                    }
                }
            }
        }

        offset += extLen;
    }

    return FALSE;
}

// ============================================================================
// QUIC Initial 패킷에서 SNI 파싱 
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN ExtractSniFromQuicInitial(
    _In_reads_bytes_(dataLen) const UCHAR * data,
    _In_ SIZE_T dataLen,
    _Out_writes_z_(sniBufferLen) CHAR * sniBuffer,
    _In_ SIZE_T sniBufferLen
)
{
    SIZE_T offset = 0;
    UCHAR firstByte;
    ULONG version;
    UCHAR dcidLen, scidLen;
    SIZE_T tokenLen;
    SIZE_T payloadLen;

    // 무조건 초기화 (분석기 경고 해결)
    if (sniBuffer == NULL || sniBufferLen < 1) {
        return FALSE;
    }
    sniBuffer[0] = '\0';

    if (data == NULL || dataLen < 20) {
        return FALSE;
    }

    firstByte = data[0];

    // QUIC Long Header 확인 (최상위 비트가 1)
    if (!(firstByte & QUIC_LONG_HEADER_MASK)) {
        return FALSE;
    }

    // Initial 패킷 타입 확인 (Long Header의 타입 비트)
    // QUIC v1에서 Initial은 0b00 타입
    UCHAR packetType = (firstByte & 0x30) >> 4;
    if (packetType != QUIC_INITIAL_TYPE) {
        return FALSE;
    }

    offset = 1;

    // Version (4 bytes)
    if (offset + 4 > dataLen) return FALSE;
    version = ((ULONG)data[offset] << 24) | ((ULONG)data[offset + 1] << 16) |
        ((ULONG)data[offset + 2] << 8) | data[offset + 3];
    offset += 4;

    // Version 0은 버전 협상 패킷
    if (version == 0) {
        return FALSE;
    }

    // DCID Length
    if (offset >= dataLen) return FALSE;
    dcidLen = data[offset++];
    if (dcidLen > 20 || offset + dcidLen > dataLen) return FALSE;
    offset += dcidLen;  // Skip DCID

    // SCID Length
    if (offset >= dataLen) return FALSE;
    scidLen = data[offset++];
    if (scidLen > 20 || offset + scidLen > dataLen) return FALSE;
    offset += scidLen;  // Skip SCID

    // Token Length (Variable-Length Integer)
    if (offset >= dataLen) return FALSE;
    UCHAR tokenLenFirstByte = data[offset];
    UCHAR tokenLenLen = 1 << (tokenLenFirstByte >> 6);

    if (tokenLenLen == 1) {
        tokenLen = tokenLenFirstByte & 0x3F;
        offset += 1;
    }
    else if (tokenLenLen == 2) {
        if (offset + 2 > dataLen) return FALSE;
        tokenLen = ((SIZE_T)(data[offset] & 0x3F) << 8) | data[offset + 1];
        offset += 2;
    }
    else if (tokenLenLen == 4) {
        if (offset + 4 > dataLen) return FALSE;
        tokenLen = ((SIZE_T)(data[offset] & 0x3F) << 24) |
            ((SIZE_T)data[offset + 1] << 16) |
            ((SIZE_T)data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
    }
    else {
        return FALSE;  // 8-byte length는 실제로 거의 사용되지 않음
    }

    // Skip Token
    if (offset + tokenLen > dataLen) return FALSE;
    offset += tokenLen;

    // Payload Length (Variable-Length Integer)
    if (offset >= dataLen) return FALSE;
    UCHAR payloadLenFirstByte = data[offset];
    UCHAR payloadLenLen = 1 << (payloadLenFirstByte >> 6);

    if (payloadLenLen == 1) {
        payloadLen = payloadLenFirstByte & 0x3F;
        offset += 1;
    }
    else if (payloadLenLen == 2) {
        if (offset + 2 > dataLen) return FALSE;
        payloadLen = ((SIZE_T)(data[offset] & 0x3F) << 8) | data[offset + 1];
        offset += 2;
    }
    else {
        // 더 큰 길이는 필요 없음
        return FALSE;
    }

    // 패킷 번호 건너뛰기 (암호화되어 있지만 Initial은 첫 바이트가 예측 가능)
    // QUIC Initial의 페이로드는 암호화되어 있지만, ClientHello의 SNI는
    // CRYPTO 프레임 내 평문으로 존재 (Initial 키는 DCID에서 파생)
    // 
    // 완전한 QUIC 복호화는 복잡하므로, 여기서는 패턴 매칭 시도
    // SNI는 TLS ClientHello 내에 평문으로 있어서 패턴 검색 가능

    // 나머지 데이터에서 SNI 패턴 검색
    // TLS extension type 0x0000 (SNI) 다음에 hostname이 옴
    for (SIZE_T i = offset; i + 10 < dataLen && i + 10 < offset + payloadLen; i++) {
        // SNI extension 시그니처: 00 00 xx xx (extension type, length)
        // 그 다음: xx xx (list length), 00 (hostname type), xx xx (name length)
        if (data[i] == 0x00 && data[i + 1] == 0x00) {
            SIZE_T extOffset = i + 2;
            if (extOffset + 2 > dataLen) continue;

            USHORT extLen = ((USHORT)data[extOffset] << 8) | data[extOffset + 1];
            if (extLen < 5 || extLen > 260) continue;

            extOffset += 2;
            if (extOffset + 2 > dataLen) continue;

            // SNI List Length
            extOffset += 2;
            if (extOffset >= dataLen) continue;

            // Name Type (0x00 = hostname)
            if (data[extOffset] != 0x00) continue;
            extOffset++;

            if (extOffset + 2 > dataLen) continue;
            USHORT nameLen = ((USHORT)data[extOffset] << 8) | data[extOffset + 1];
            extOffset += 2;

            if (nameLen > 0 && nameLen < 256 && nameLen < sniBufferLen - 1 &&
                extOffset + nameLen <= dataLen) {
                // 유효한 호스트명 문자 확인
                BOOLEAN valid = TRUE;
                for (SIZE_T j = 0; j < nameLen; j++) {
                    UCHAR c = data[extOffset + j];
                    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '-')) {
                        valid = FALSE;
                        break;
                    }
                }

                if (valid) {
                    RtlCopyMemory(sniBuffer, &data[extOffset], nameLen);
                    sniBuffer[nameLen] = '\0';
                    ToLowerCase(sniBuffer, sniBufferLen);
                    KdPrint(("WFP QUIC: Extracted SNI from Initial: %s\n", sniBuffer));
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

// ============================================================================
// DNS 응답에서 도메인과 IP 추출 
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
void ParseDnsResponseForBlocking(
    _In_ const UCHAR * data,
    _In_ SIZE_T dataLen
)
{
    // DNS 응답 구조:
    // Header (12 bytes)
    // Questions
    // Answers (우리가 관심 있는 부분)

    if (data == NULL || dataLen < 12) {
        return;
    }

    // DNS Header 확인
    // Flags: QR=1 (응답), RCODE=0 (성공)
    USHORT flags = ((USHORT)data[2] << 8) | data[3];
    if (!(flags & 0x8000)) {  // QR 비트가 0이면 쿼리
        return;
    }
    if ((flags & 0x000F) != 0) {  // RCODE != 0이면 에러
        return;
    }

    USHORT qdCount = ((USHORT)data[4] << 8) | data[5];
    USHORT anCount = ((USHORT)data[6] << 8) | data[7];

    if (anCount == 0) {
        return;
    }

    SIZE_T offset = 12;

    // Question 섹션 건너뛰기
    for (USHORT i = 0; i < qdCount && offset < dataLen; i++) {
        // 도메인 이름 건너뛰기
        while (offset < dataLen && data[offset] != 0) {
            if ((data[offset] & 0xC0) == 0xC0) {
                // 압축 포인터
                offset += 2;
                goto skip_question_name;
            }
            offset += 1 + data[offset];  // 라벨 길이 + 라벨
        }
        offset++;  // Null terminator
    skip_question_name:
        offset += 4;  // QTYPE (2) + QCLASS (2)
    }

    // Answer 섹션 파싱
    CHAR domainName[MAX_SNI_LENGTH];

    for (USHORT i = 0; i < anCount && offset + 12 <= dataLen; i++) {
        domainName[0] = '\0';
        // SIZE_T nameStart = offset;

         // 도메인 이름 추출
        SIZE_T nameOffset = offset;
        SIZE_T nameLen = 0;

        while (nameOffset < dataLen && data[nameOffset] != 0) {
            if ((data[nameOffset] & 0xC0) == 0xC0) {
                // 압축 포인터
                if (nameOffset + 1 >= dataLen) break;
                SIZE_T ptrOffset = ((SIZE_T)(data[nameOffset] & 0x3F) << 8) | data[nameOffset + 1];

                // 포인터가 가리키는 위치에서 이름 추출
                while (ptrOffset < dataLen && data[ptrOffset] != 0) {
                    UCHAR labelLen = data[ptrOffset];
                    if ((labelLen & 0xC0) == 0xC0) break;  // 중첩 압축
                    if (ptrOffset + 1 + labelLen > dataLen) break;

                    if (nameLen > 0 && nameLen < MAX_SNI_LENGTH - 1) {
                        domainName[nameLen++] = '.';
                    }
                    for (UCHAR j = 0; j < labelLen && nameLen < MAX_SNI_LENGTH - 1; j++) {
                        domainName[nameLen++] = (CHAR)data[ptrOffset + 1 + j];
                    }
                    ptrOffset += 1 + labelLen;
                }

                offset += 2;
                goto parse_record;
            }

            UCHAR labelLen = data[nameOffset];
            if (nameOffset + 1 + labelLen > dataLen) break;

            if (nameLen > 0 && nameLen < MAX_SNI_LENGTH - 1) {
                domainName[nameLen++] = '.';
            }
            for (UCHAR j = 0; j < labelLen && nameLen < MAX_SNI_LENGTH - 1; j++) {
                domainName[nameLen++] = (CHAR)data[nameOffset + 1 + j];
            }
            nameOffset += 1 + labelLen;
        }

        if (data[nameOffset] == 0) {
            offset = nameOffset + 1;
        }

    parse_record:
        domainName[nameLen] = '\0';
        ToLowerCase(domainName, MAX_SNI_LENGTH);

        if (offset + 10 > dataLen) break;

        USHORT rrType = ((USHORT)data[offset] << 8) | data[offset + 1];
        offset += 2;  // TYPE
        offset += 2;  // CLASS
        offset += 4;  // TTL
        USHORT rdLength = ((USHORT)data[offset] << 8) | data[offset + 1];
        offset += 2;

        if (offset + rdLength > dataLen) break;

        // A 레코드 (IPv4)
        if (rrType == 1 && rdLength == 4) {
            ULONG ipAddress = ((ULONG)data[offset] << 24) |
                ((ULONG)data[offset + 1] << 16) |
                ((ULONG)data[offset + 2] << 8) |
                data[offset + 3];

            // 이 도메인이 차단 리스트에 있는지 확인
            if (domainName[0] != '\0' && IsSniInBlockList(domainName)) {
                AddBlockedIp(ipAddress, domainName);
                KdPrint(("WFP DNS: Cached IP %u.%u.%u.%u for blocked domain %s\n",
                    (ipAddress >> 24) & 0xFF, (ipAddress >> 16) & 0xFF,
                    (ipAddress >> 8) & 0xFF, ipAddress & 0xFF, domainName));
            }
        }

        offset += rdLength;
    }
}

// ============================================================================
// DNS 싱크홀 함수 
// ============================================================================

// DNS 싱크홀 초기화
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS InitializeDnsSinkhole(void)
{
    if (g_DriverContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 기본값 설정
    g_DriverContext->DnsSinkholeEnabled = 0;  // 기본 비활성화
    g_DriverContext->SinkholeIp = DNS_SINKHOLE_DEFAULT_IP;  // 127.0.0.1
    g_DriverContext->SinkholeHttpPort = DNS_SINKHOLE_HTTP_PORT;
    g_DriverContext->SinkholeHttpsPort = DNS_SINKHOLE_HTTPS_PORT;
    g_DriverContext->TotalDnsModified = 0;
    g_DriverContext->TotalSinkholeRedirected = 0;
    KeInitializeSpinLock(&g_DriverContext->DnsSinkholeLock);

    KdPrint(("WFP DNS Sinkhole: Initialized (default IP: 127.0.0.1)\n"));
    return STATUS_SUCCESS;
}

// DNS 이름 추출 (압축 포인터 지원)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return > 0)
SIZE_T ExtractDnsName(
    _In_reads_bytes_(dataLen) const UCHAR * data,
    _In_ SIZE_T dataLen,
    _In_ SIZE_T offset,
    _Out_writes_z_(nameBufferLen) CHAR * nameBuffer,
    _In_ SIZE_T nameBufferLen
)
{
    SIZE_T nameLen = 0;
    SIZE_T currentOffset = offset;
    BOOLEAN jumped = FALSE;
    SIZE_T jumpCount = 0;
    const SIZE_T MAX_JUMPS = 10;  // 무한 루프 방지

    if (nameBuffer == NULL || nameBufferLen < 1) {
        return 0;
    }
    nameBuffer[0] = '\0';

    if (data == NULL || offset >= dataLen) {
        return 0;
    }

    while (currentOffset < dataLen && jumpCount < MAX_JUMPS) {
        UCHAR labelLen = data[currentOffset];

        if (labelLen == 0) {
            // 이름 끝
            if (!jumped) {
                currentOffset++;
            }
            break;
        }

        if ((labelLen & 0xC0) == 0xC0) {
            // 압축 포인터
            if (currentOffset + 1 >= dataLen) break;

            SIZE_T ptrOffset = ((SIZE_T)(labelLen & 0x3F) << 8) | data[currentOffset + 1];

            if (!jumped) {
                // 첫 번째 점프: 원래 위치 기록
                offset = currentOffset + 2;
                jumped = TRUE;
            }

            currentOffset = ptrOffset;
            jumpCount++;
            continue;
        }

        // 일반 라벨
        if (currentOffset + 1 + labelLen > dataLen) break;

        if (nameLen > 0 && nameLen < nameBufferLen - 1) {
            nameBuffer[nameLen++] = '.';
        }

        for (UCHAR j = 0; j < labelLen && nameLen < nameBufferLen - 1; j++) {
            nameBuffer[nameLen++] = (CHAR)data[currentOffset + 1 + j];
        }

        currentOffset += 1 + labelLen;
    }

    nameBuffer[nameLen] = '\0';
    ToLowerCase(nameBuffer, nameBufferLen);

    return jumped ? (offset - offset + 2) : (currentOffset - offset);
}

// DNS 응답 수정 (싱크홀용)
// 반환값: TRUE = 수정됨, FALSE = 수정 안됨
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN ModifyDnsResponseForSinkhole(
    _Inout_updates_bytes_(dataLen) UCHAR * data,
    _In_ SIZE_T dataLen
)
{
    BOOLEAN modified = FALSE;
    ULONG sinkholeIp;
    KIRQL oldIrql;

    if (g_DriverContext == NULL || data == NULL || dataLen < 12) {
        return FALSE;
    }

    // 싱크홀이 비활성화되어 있으면 종료
    if (g_DriverContext->DnsSinkholeEnabled == 0) {
        return FALSE;
    }

    // 싱크홀 IP 가져오기
    KeAcquireSpinLock(&g_DriverContext->DnsSinkholeLock, &oldIrql);
    sinkholeIp = g_DriverContext->SinkholeIp;
    KeReleaseSpinLock(&g_DriverContext->DnsSinkholeLock, oldIrql);

    // DNS Header 확인
    USHORT flags = ((USHORT)data[2] << 8) | data[3];
    if (!(flags & 0x8000)) {  // QR 비트가 0이면 쿼리
        return FALSE;
    }
    if ((flags & 0x000F) != 0) {  // RCODE != 0이면 에러
        return FALSE;
    }

    USHORT qdCount = ((USHORT)data[4] << 8) | data[5];
    USHORT anCount = ((USHORT)data[6] << 8) | data[7];

    if (anCount == 0) {
        return FALSE;
    }

    SIZE_T offset = 12;

    // Question 섹션 건너뛰기
    for (USHORT i = 0; i < qdCount && offset < dataLen; i++) {
        while (offset < dataLen && data[offset] != 0) {
            if ((data[offset] & 0xC0) == 0xC0) {
                offset += 2;
                goto skip_question;
            }
            offset += 1 + data[offset];
        }
        offset++;
    skip_question:
        offset += 4;  // QTYPE + QCLASS
    }

    // Answer 섹션 파싱 및 수정
    CHAR domainName[MAX_SNI_LENGTH];

    for (USHORT i = 0; i < anCount && offset + 12 <= dataLen; i++) {
        domainName[0] = '\0';


        // 도메인 이름 추출
        SIZE_T nameOffset = offset;
        SIZE_T nameLen = 0;

        while (nameOffset < dataLen && data[nameOffset] != 0) {
            if ((data[nameOffset] & 0xC0) == 0xC0) {
                // 압축 포인터
                if (nameOffset + 1 >= dataLen) break;
                SIZE_T ptrOffset = ((SIZE_T)(data[nameOffset] & 0x3F) << 8) | data[nameOffset + 1];

                // 포인터가 가리키는 위치에서 이름 추출
                while (ptrOffset < dataLen && data[ptrOffset] != 0) {
                    UCHAR labelLen = data[ptrOffset];
                    if ((labelLen & 0xC0) == 0xC0) break;
                    if (ptrOffset + 1 + labelLen > dataLen) break;

                    if (nameLen > 0 && nameLen < MAX_SNI_LENGTH - 1) {
                        domainName[nameLen++] = '.';
                    }
                    for (UCHAR j = 0; j < labelLen && nameLen < MAX_SNI_LENGTH - 1; j++) {
                        domainName[nameLen++] = (CHAR)data[ptrOffset + 1 + j];
                    }
                    ptrOffset += 1 + labelLen;
                }

                offset += 2;
                goto parse_answer;
            }

            UCHAR labelLen = data[nameOffset];
            if (nameOffset + 1 + labelLen > dataLen) break;

            if (nameLen > 0 && nameLen < MAX_SNI_LENGTH - 1) {
                domainName[nameLen++] = '.';
            }
            for (UCHAR j = 0; j < labelLen && nameLen < MAX_SNI_LENGTH - 1; j++) {
                domainName[nameLen++] = (CHAR)data[nameOffset + 1 + j];
            }
            nameOffset += 1 + labelLen;
        }

        if (nameOffset < dataLen && data[nameOffset] == 0) {
            offset = nameOffset + 1;
        }

    parse_answer:
        domainName[nameLen] = '\0';
        ToLowerCase(domainName, MAX_SNI_LENGTH);

        if (offset + 10 > dataLen) break;

        USHORT rrType = ((USHORT)data[offset] << 8) | data[offset + 1];
        offset += 2;  // TYPE
        offset += 2;  // CLASS
        offset += 4;  // TTL
        USHORT rdLength = ((USHORT)data[offset] << 8) | data[offset + 1];
        offset += 2;

        if (offset + rdLength > dataLen) break;

        // A 레코드 (IPv4) 이고 차단 대상 도메인인 경우 IP 수정
        if (rrType == 1 && rdLength == 4) {
            if (domainName[0] != '\0' && IsSniInBlockList(domainName)) {
                // 기존 IP 로깅
                ULONG originalIp = ((ULONG)data[offset] << 24) |
                    ((ULONG)data[offset + 1] << 16) |
                    ((ULONG)data[offset + 2] << 8) |
                    data[offset + 3];

                // 싱크홀 IP로 수정 (네트워크 바이트 오더로 변환)
                data[offset] = (UCHAR)((sinkholeIp >> 24) & 0xFF);
                data[offset + 1] = (UCHAR)((sinkholeIp >> 16) & 0xFF);
                data[offset + 2] = (UCHAR)((sinkholeIp >> 8) & 0xFF);
                data[offset + 3] = (UCHAR)(sinkholeIp & 0xFF);

                modified = TRUE;
                InterlockedIncrement64(&g_DriverContext->TotalDnsModified);

                KdPrint(("WFP DNS Sinkhole: Modified %s: %u.%u.%u.%u -> %u.%u.%u.%u\n",
                    domainName,
                    (originalIp >> 24) & 0xFF, (originalIp >> 16) & 0xFF,
                    (originalIp >> 8) & 0xFF, originalIp & 0xFF,
                    (sinkholeIp >> 24) & 0xFF, (sinkholeIp >> 16) & 0xFF,
                    (sinkholeIp >> 8) & 0xFF, sinkholeIp & 0xFF));
            }
        }

        offset += rdLength;
    }

    return modified;
}

// ============================================================================
// 패킷 큐 함수
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS InitializePacketQueue(void)
{
    if (g_DriverContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    g_DriverContext->PacketQueue = (PPACKET_RING_BUFFER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(PACKET_RING_BUFFER),
        'QPFW'
    );

    if (g_DriverContext->PacketQueue == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_DriverContext->PacketQueue, sizeof(PACKET_RING_BUFFER));
    KeInitializeSpinLock(&g_DriverContext->PacketQueue->Lock);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
void CleanupPacketQueue(void)
{
    if (g_DriverContext != NULL && g_DriverContext->PacketQueue != NULL) {
        ExFreePoolWithTag(g_DriverContext->PacketQueue, 'QPFW');
        g_DriverContext->PacketQueue = NULL;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN EnqueuePacket(_In_ const PACKET_INFO * pPacket)
{
    BOOLEAN result = FALSE;
    KLOCK_QUEUE_HANDLE lockHandle;
    PPACKET_RING_BUFFER queue;

    if (g_DriverContext == NULL || g_DriverContext->PacketQueue == NULL || pPacket == NULL) {
        return FALSE;
    }

    queue = g_DriverContext->PacketQueue;

    KeAcquireInStackQueuedSpinLock(&queue->Lock, &lockHandle);

    if (queue->Count < PACKET_QUEUE_SIZE) {
        LONG head = queue->Head;
        RtlCopyMemory(&queue->Entries[head].Info, pPacket, sizeof(PACKET_INFO));
        queue->Head = (head + 1) % PACKET_QUEUE_SIZE;
        InterlockedIncrement(&queue->Count);
        result = TRUE;
    }
    else {
        InterlockedIncrement64(&g_DriverContext->DroppedPackets);
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    return result;
}

_IRQL_requires_max_(APC_LEVEL)
ULONG DequeuePacketBatch(_Out_ PACKET_BATCH * pBatch)
{
    ULONG count = 0;
    KLOCK_QUEUE_HANDLE lockHandle;
    PPACKET_RING_BUFFER queue;
    KIRQL oldIrql;

    // 먼저 출력 버퍼 초기화
    if (pBatch != NULL) {
        RtlZeroMemory(pBatch, sizeof(PACKET_BATCH));
    }

    if (g_DriverContext == NULL || g_DriverContext->PacketQueue == NULL || pBatch == NULL) {
        return 0;
    }

    queue = g_DriverContext->PacketQueue;

    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    KeAcquireInStackQueuedSpinLock(&queue->Lock, &lockHandle);

    while (count < MAX_PACKETS_PER_BATCH && queue->Count > 0) {
        LONG tail = queue->Tail;
        RtlCopyMemory(&pBatch->Packets[count], &queue->Entries[tail].Info, sizeof(PACKET_INFO));
        queue->Tail = (tail + 1) % PACKET_QUEUE_SIZE;
        InterlockedDecrement(&queue->Count);
        count++;
    }

    pBatch->PacketCount = count;
    pBatch->RemainingPackets = (ULONG)queue->Count;
    pBatch->SequenceNumber = (ULONG)InterlockedIncrement(&g_DriverContext->BatchSequence);

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    KeLowerIrql(oldIrql);

    return count;
}

_IRQL_requires_max_(APC_LEVEL)
void ClearPacketQueueInternal(void)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PPACKET_RING_BUFFER queue;
    KIRQL oldIrql;

    if (g_DriverContext == NULL || g_DriverContext->PacketQueue == NULL) {
        return;
    }

    queue = g_DriverContext->PacketQueue;

    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    KeAcquireInStackQueuedSpinLock(&queue->Lock, &lockHandle);

    queue->Head = 0;
    queue->Tail = 0;
    queue->Count = 0;

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    KeLowerIrql(oldIrql);
}


void NTAPI FilterClassifyConnect(
    _In_ const FWPS_INCOMING_VALUES0 * inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 * inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1 * filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 * classifyOut
)
{
    PACKET_INFO packetInfo = { 0 };
    BOOLEAN shouldBlock = FALSE;
    BOOLEAN shouldCapture = FALSE;
    ULONG targetPid = 0;
    UINT64 processPid = 0;
    ULONG remoteAddress = 0;
    USHORT remotePort = 0;
    UCHAR protocol = 0;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (classifyOut == NULL) {
        return;
    }

    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (g_DriverContext == NULL) {
        return;
    }

    if (inMetaValues == NULL || inFixedValues == NULL) {
        return;
    }

    // 설정 확인
    targetPid = g_DriverContext->BlockedPid;
    shouldCapture = (g_DriverContext->CaptureEnabled != 0);

    // PID 확인
    if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0) {
        processPid = inMetaValues->processId;
        if (targetPid != 0 && processPid == (UINT64)targetPid) {
            shouldBlock = TRUE;
        }
    }

    // IP/Port/Protocol 정보 추출
    if (inFixedValues->incomingValue != NULL) {
        if (inFixedValues->valueCount > FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS) {
            remoteAddress = inFixedValues->incomingValue[
                FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        }
        if (inFixedValues->valueCount > FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT) {
            remotePort = inFixedValues->incomingValue[
                FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
        }
        if (inFixedValues->valueCount > FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL) {
            protocol = inFixedValues->incomingValue[
                FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
        }
    }

    // HTTPS/QUIC 포트(443)로 나가는 연결에 대해 IP 캐시 확인
    // 단, 루프백 주소(127.0.0.0/8)는 제외 (싱크홀 서버 연결 허용)
    if (!shouldBlock && g_DriverContext->SniBlockingEnabled && remotePort == 443) {
        // 버그 수정: IsIpBlockedWithSniIncrement 사용하여 연관된 SNI의 차단 횟수도 증가시킴
        if (!IsLoopbackAddress(remoteAddress) && IsIpBlockedWithSniIncrement(remoteAddress)) {
            shouldBlock = TRUE;
            InterlockedIncrement64(&g_DriverContext->DnsBlocked);  // IP 캐시 기반 차단 통계
            KdPrint(("WFP Connect: Blocking %s connection to cached IP %u.%u.%u.%u:443 (PID=%llu)\n",
                (protocol == PROTO_TCP) ? "TCP" : "UDP",
                (remoteAddress >> 24) & 0xFF,
                (remoteAddress >> 16) & 0xFF,
                (remoteAddress >> 8) & 0xFF,
                remoteAddress & 0xFF,
                processPid));
        }
    }

    // 캡처 데이터 수집
    if (shouldCapture || shouldBlock) {
        packetInfo.Timestamp = GetCurrentTimestamp();
        packetInfo.ProcessId = (ULONG)processPid;
        packetInfo.Direction = PACKET_DIR_OUTBOUND;

        if (inFixedValues->incomingValue != NULL) {
            if (inFixedValues->valueCount > FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS) {
                packetInfo.LocalAddress = inFixedValues->incomingValue[
                    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
            }
            packetInfo.RemoteAddress = remoteAddress;

            if (inFixedValues->valueCount > FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT) {
                packetInfo.LocalPort = inFixedValues->incomingValue[
                    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
            }
            packetInfo.RemotePort = remotePort;
            packetInfo.Protocol = protocol;
        }

        packetInfo.Action = shouldBlock ? PACKET_ACTION_BLOCK : PACKET_ACTION_PERMIT;

        // 버그 수정: 차단된 패킷도 캡처 여부와 관계없이 큐에 추가
        if (shouldCapture || shouldBlock) {
            EnqueuePacket(&packetInfo);
            InterlockedIncrement64(&g_DriverContext->TotalCaptured);
        }
    }

    // 차단 처리
    if (shouldBlock) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        InterlockedIncrement64(&g_DriverContext->TotalBlocked);
    }
}

// ============================================================================
// SNI Stream Classify 콜백 
// ============================================================================

void NTAPI FilterClassifyStream(
    _In_ const FWPS_INCOMING_VALUES0 * inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 * inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1 * filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 * classifyOut
)
{
    FWPS_STREAM_CALLOUT_IO_PACKET0* streamPacket;
    FWPS_STREAM_DATA0* streamData;
    CHAR sniBuffer[MAX_SNI_LENGTH];
    BOOLEAN shouldBlock = FALSE;
    ULONG remoteIp = 0;
    ULONG localIp = 0;
    USHORT remotePort = 0;
    USHORT localPort = 0;
    UINT64 processPid = 0;

    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (classifyOut == NULL) {
        return;
    }
    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (g_DriverContext == NULL || g_DriverContext->SniBlockingEnabled == 0) {
        return;
    }

    if (layerData == NULL) {
        return;
    }

    // PID 추출 (버그 수정: inMetaValues 사용)
    if (inMetaValues != NULL &&
        (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0) {
        processPid = inMetaValues->processId;
    }

    // IP/Port 정보 추출
    if (inFixedValues != NULL && inFixedValues->incomingValue != NULL) {
        if (inFixedValues->valueCount > FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS) {
            remoteIp = inFixedValues->incomingValue[
                FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS].value.uint32;
        }
        if (inFixedValues->valueCount > FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS) {
            localIp = inFixedValues->incomingValue[
                FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS].value.uint32;
        }
        if (inFixedValues->valueCount > FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT) {
            remotePort = inFixedValues->incomingValue[
                FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT].value.uint16;
        }
        if (inFixedValues->valueCount > FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT) {
            localPort = inFixedValues->incomingValue[
                FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT].value.uint16;
        }
    }

    // 루프백 주소는 검사하지 않음 (싱크홀 서버 연결 허용)
    if (IsLoopbackAddress(remoteIp)) {
        return;
    }

    streamPacket = (FWPS_STREAM_CALLOUT_IO_PACKET0*)layerData;
    streamData = streamPacket->streamData;

    if (streamData == NULL || streamData->dataLength == 0) {
        return;
    }

    // Outbound 데이터만 검사
    if (!(streamData->flags & FWPS_STREAM_FLAG_SEND)) {
        return;
    }

    // 데이터 버퍼 처리
    if (streamData->netBufferListChain != NULL) {
        NET_BUFFER_LIST* nbl = streamData->netBufferListChain;
        NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);

        if (nb != NULL) {
            ULONG dataLength = NET_BUFFER_DATA_LENGTH(nb);

            if (dataLength >= 50 && dataLength < 16384) {
                UCHAR* dataBuffer = (UCHAR*)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    dataLength,
                    'TLSB'
                );

                if (dataBuffer != NULL) {
                    UCHAR* mappedData = (UCHAR*)NdisGetDataBuffer(nb, dataLength, dataBuffer, 1, 0);

                    if (mappedData != NULL) {
                        // TLS Handshake (0x16)
                        if (mappedData[0] == 0x16) {
                            sniBuffer[0] = '\0';

                            if (ExtractSniFromTlsClientHello(mappedData, dataLength, sniBuffer, MAX_SNI_LENGTH)) {
                                if (IsSniBlocked(sniBuffer)) {
                                    shouldBlock = TRUE;
                                    KdPrint(("WFP Stream: Blocking TLS to %s\n", sniBuffer));

                                    // IP 캐시에 추가 (향후 연결 차단용)
                                    if (remoteIp != 0) {
                                        AddBlockedIp(remoteIp, sniBuffer);
                                    }
                                }
                            }
                        }
                    }

                    ExFreePoolWithTag(dataBuffer, 'TLSB');
                }
            }
        }
    }

    // 차단 처리 - 즉시 연결 끊기
    if (shouldBlock) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

        // 스트림 연결 즉시 드롭
        streamPacket->streamAction = FWPS_STREAM_ACTION_DROP_CONNECTION;
        streamPacket->countBytesEnforced = 0;

        // 버그 수정: 차단된 패킷 정보를 큐에 추가하여 UI에 표시
        {
            PACKET_INFO packetInfo = { 0 };
            packetInfo.Timestamp = GetCurrentTimestamp();
            packetInfo.ProcessId = (ULONG)processPid;
            packetInfo.LocalAddress = localIp;
            packetInfo.RemoteAddress = remoteIp;
            packetInfo.LocalPort = localPort;
            packetInfo.RemotePort = remotePort;
            packetInfo.Protocol = PROTO_TCP;
            packetInfo.Direction = PACKET_DIR_OUTBOUND;
            packetInfo.Action = PACKET_ACTION_BLOCK;

            EnqueuePacket(&packetInfo);
            InterlockedIncrement64(&g_DriverContext->TotalCaptured);
        }

        InterlockedIncrement64(&g_DriverContext->TotalBlocked);
    }
}

// ============================================================================
// QUIC 차단 콜백 
// ============================================================================

void NTAPI FilterClassifyQuic(
    _In_ const FWPS_INCOMING_VALUES0 * inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 * inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1 * filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 * classifyOut
)
{
    ULONG remoteAddress = 0;
    ULONG localAddress = 0;
    USHORT remotePort = 0;
    USHORT localPort = 0;
    BOOLEAN shouldBlock = FALSE;
    CHAR sniBuffer[MAX_SNI_LENGTH];
    UINT64 processPid = 0;

    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (classifyOut == NULL) {
        return;
    }
    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (g_DriverContext == NULL ||
        g_DriverContext->SniBlockingEnabled == 0 ||
        g_DriverContext->QuicBlockingEnabled == 0) {
        return;
    }

    if (inFixedValues == NULL || inFixedValues->incomingValue == NULL) {
        return;
    }

    // PID 추출 (버그 수정)
    if (inMetaValues != NULL &&
        (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0) {
        processPid = inMetaValues->processId;
    }

    // IP/Port 정보 추출
    if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS) {
        remoteAddress = inFixedValues->incomingValue[
            FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;
    }
    if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT) {
        remotePort = inFixedValues->incomingValue[
            FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
    }
    if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS) {
        localAddress = inFixedValues->incomingValue[
            FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value.uint32;
    }
    if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT) {
        localPort = inFixedValues->incomingValue[
            FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value.uint16;
    }

    // UDP 443 (QUIC) 트래픽 확인
    if (remotePort != 443) {
        return;
    }

    // 루프백 주소는 검사하지 않음 (싱크홀 서버 연결 허용)
    if (IsLoopbackAddress(remoteAddress)) {
        return;
    }

    // 먼저 IP 캐시 확인 (버그 수정: IsIpBlockedWithSniIncrement 사용)
    if (IsIpBlockedWithSniIncrement(remoteAddress)) {
        shouldBlock = TRUE;
        InterlockedIncrement64(&g_DriverContext->QuicTotalBlocked);
        KdPrint(("WFP QUIC: Blocking cached IP %u.%u.%u.%u:443\n",
            (remoteAddress >> 24) & 0xFF,
            (remoteAddress >> 16) & 0xFF,
            (remoteAddress >> 8) & 0xFF,
            remoteAddress & 0xFF));
    }

    // QUIC Initial 패킷에서 SNI 파싱 시도
    if (!shouldBlock && layerData != NULL) {
        FWPS_STREAM_CALLOUT_IO_PACKET0* packet = (FWPS_STREAM_CALLOUT_IO_PACKET0*)layerData;

        // DATAGRAM_DATA에서는 NET_BUFFER_LIST 직접 접근
        if (inMetaValues != NULL) {
            NET_BUFFER_LIST* nbl = NULL;

            // 다양한 방법으로 데이터 접근 시도
            // (DATAGRAM_DATA 레이어의 layerData 형식에 따라 다름)
            if (packet != NULL) {
                // 직접 NET_BUFFER_LIST 캐스트 시도
                nbl = (NET_BUFFER_LIST*)layerData;

                if (nbl != NULL) {
                    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);

                    if (nb != NULL) {
                        ULONG dataLength = NET_BUFFER_DATA_LENGTH(nb);

                        if (dataLength >= 20 && dataLength < 4096) {
                            UCHAR* dataBuffer = (UCHAR*)ExAllocatePool2(
                                POOL_FLAG_NON_PAGED,
                                dataLength,
                                'QUIB'
                            );

                            if (dataBuffer != NULL) {
                                UCHAR* mappedData = (UCHAR*)NdisGetDataBuffer(
                                    nb, dataLength, dataBuffer, 1, 0);

                                if (mappedData != NULL) {
                                    sniBuffer[0] = '\0';

                                    if (ExtractSniFromQuicInitial(mappedData, dataLength,
                                        sniBuffer, MAX_SNI_LENGTH)) {
                                        if (IsSniBlocked(sniBuffer)) {
                                            shouldBlock = TRUE;
                                            InterlockedIncrement64(&g_DriverContext->QuicTotalBlocked);

                                            // IP 캐시에 추가
                                            AddBlockedIp(remoteAddress, sniBuffer);

                                            KdPrint(("WFP QUIC: Blocking Initial to %s (IP added to cache)\n",
                                                sniBuffer));
                                        }
                                    }
                                }

                                ExFreePoolWithTag(dataBuffer, 'QUIB');
                            }
                        }
                    }
                }
            }
        }
    }

    if (shouldBlock) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

        // 버그 수정: 차단된 패킷 정보를 큐에 추가하여 UI에 표시
        {
            PACKET_INFO packetInfo = { 0 };
            packetInfo.Timestamp = GetCurrentTimestamp();
            packetInfo.ProcessId = (ULONG)processPid;
            packetInfo.LocalAddress = localAddress;
            packetInfo.RemoteAddress = remoteAddress;
            packetInfo.LocalPort = localPort;
            packetInfo.RemotePort = remotePort;
            packetInfo.Protocol = PROTO_UDP;
            packetInfo.Direction = PACKET_DIR_OUTBOUND;
            packetInfo.Action = PACKET_ACTION_BLOCK;

            EnqueuePacket(&packetInfo);
            InterlockedIncrement64(&g_DriverContext->TotalCaptured);
        }

        InterlockedIncrement64(&g_DriverContext->TotalBlocked);
    }
}

// ============================================================================
// DNS 모니터링 및 싱크홀 콜백 (v3.0 개선)
// ============================================================================

void NTAPI FilterClassifyDns(
    _In_ const FWPS_INCOMING_VALUES0 * inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 * inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1 * filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 * classifyOut
)
{
    USHORT remotePort = 0;
    ULONG direction = 0;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (classifyOut == NULL) {
        return;
    }
    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (g_DriverContext == NULL ||
        g_DriverContext->SniBlockingEnabled == 0 ||
        g_DriverContext->DnsMonitoringEnabled == 0) {
        return;
    }

    if (inFixedValues == NULL || inFixedValues->incomingValue == NULL) {
        return;
    }

    // DNS 응답 확인 (소스 포트 53)
    if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT) {
        remotePort = inFixedValues->incomingValue[
            FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
    }

    // 방향 확인 (인바운드만 처리)
    if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION) {
        direction = inFixedValues->incomingValue[
            FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint32;
    }

    // 인바운드 DNS 응답만 처리 (FWP_DIRECTION_INBOUND = 1)
    if (direction != FWP_DIRECTION_INBOUND) {
        return;
    }

    if (layerData != NULL) {
        NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;

        if (nbl != NULL) {
            NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);

            if (nb != NULL) {
                ULONG dataLength = NET_BUFFER_DATA_LENGTH(nb);

                if (dataLength >= 12 && dataLength < 4096) {
                    // DNS 싱크홀이 활성화된 경우 패킷 직접 수정 시도
                    if (g_DriverContext->DnsSinkholeEnabled != 0) {
                        // MDL을 통해 실제 데이터에 접근
                        MDL* mdl = NET_BUFFER_CURRENT_MDL(nb);
                        ULONG mdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(nb);

                        if (mdl != NULL) {
                            UCHAR* mdlData = (UCHAR*)MmGetSystemAddressForMdlSafe(
                                mdl, NormalPagePriority | MdlMappingNoExecute);

                            if (mdlData != NULL) {
                                UCHAR* dnsData = mdlData + mdlOffset;
                                ULONG availableLen = MmGetMdlByteCount(mdl) - mdlOffset;

                                if (availableLen >= dataLength) {
                                    // 싱크홀 수정 시도
                                    if (ModifyDnsResponseForSinkhole(dnsData, dataLength)) {
                                        KdPrint(("WFP DNS Sinkhole: Packet modified in-place\n"));
                                    }

                                    // IP 캐싱도 수행 (원본 IP가 아닌 수정된 IP로 캐싱됨)
                                    ParseDnsResponseForBlocking(dnsData, dataLength);
                                }
                            }
                        }
                    }
                    else {
                        // 싱크홀 비활성화 시 기존 방식으로 IP 캐싱만 수행
                        UCHAR* dataBuffer = (UCHAR*)ExAllocatePool2(
                            POOL_FLAG_NON_PAGED,
                            dataLength,
                            'DNSB'
                        );

                        if (dataBuffer != NULL) {
                            UCHAR* mappedData = (UCHAR*)NdisGetDataBuffer(
                                nb, dataLength, dataBuffer, 1, 0);

                            if (mappedData != NULL) {
                                ParseDnsResponseForBlocking(mappedData, dataLength);
                            }

                            ExFreePoolWithTag(dataBuffer, 'DNSB');
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Notify 콜백 함수들
// ============================================================================

NTSTATUS NTAPI FilterNotifyConnect(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID * filterKey,
    _Inout_ FWPS_FILTER1 * filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI FilterNotifyStream(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID * filterKey,
    _Inout_ FWPS_FILTER1 * filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI FilterNotifyQuic(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID * filterKey,
    _Inout_ FWPS_FILTER1 * filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI FilterNotifyDns(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID * filterKey,
    _Inout_ FWPS_FILTER1 * filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

// ============================================================================
// WFP 등록/해제
// ============================================================================

NTSTATUS RegisterWfpFilter(_In_ PDEVICE_OBJECT pDeviceObj)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SESSION0 session = { 0 };
    FWPM_CALLOUT0 mCallout = { 0 };
    FWPS_CALLOUT1 sCallout = { 0 };
    FWPM_FILTER0 filter = { 0 };
    FWPM_FILTER_CONDITION0 filterConditions[2] = { 0 };

    PAGED_CODE();

    if (g_DriverContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &g_DriverContext->EngineHandle
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpmEngineOpen0 failed: 0x%08X\n", status));
        return status;
    }

    // ========================================================================
    // 1. PID 기반 차단 + IP 캐시 차단 Callout (ALE_AUTH_CONNECT_V4)
    // ========================================================================

    mCallout.calloutKey = GUID_MY_WFP_CALLOUT;
    mCallout.displayData.name = L"WFP PID/IP Block Callout";
    mCallout.displayData.description = L"Blocks connections for specified PID and cached IPs";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    status = FwpmCalloutAdd0(g_DriverContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpmCalloutAdd0 (PID) failed: 0x%08X\n", status));
        return status;
    }

    sCallout.calloutKey = GUID_MY_WFP_CALLOUT;
    sCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN1)FilterClassifyConnect;
    sCallout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN1)FilterNotifyConnect;
    sCallout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister1(pDeviceObj, &sCallout, &g_DriverContext->CalloutIdConnect);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpsCalloutRegister1 (PID) failed: 0x%08X\n", status));
        return status;
    }

    filter.displayData.name = L"WFP PID/IP Block Filter";
    filter.displayData.description = L"Filter for PID and IP-based blocking";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = GUID_MY_WFP_CALLOUT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0x0F;

    status = FwpmFilterAdd0(
        g_DriverContext->EngineHandle,
        &filter,
        NULL,
        &g_DriverContext->FilterIdConnect
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpmFilterAdd0 (PID) failed: 0x%08X\n", status));
        return status;
    }

    KdPrint(("WFP: PID/IP filter registered\n"));

    // ========================================================================
    // 2. SNI 기반 차단 Callout (STREAM_V4)
    // ========================================================================

    RtlZeroMemory(&mCallout, sizeof(mCallout));
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    RtlZeroMemory(&filter, sizeof(filter));

    mCallout.calloutKey = GUID_MY_WFP_SNI_CALLOUT;
    mCallout.displayData.name = L"WFP SNI Block Callout";
    mCallout.displayData.description = L"Blocks TLS connections based on SNI";
    mCallout.applicableLayer = FWPM_LAYER_STREAM_V4;

    status = FwpmCalloutAdd0(g_DriverContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpmCalloutAdd0 (SNI) failed: 0x%08X\n", status));
        goto SkipSni;
    }

    sCallout.calloutKey = GUID_MY_WFP_SNI_CALLOUT;
    sCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN1)FilterClassifyStream;
    sCallout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN1)FilterNotifyStream;
    sCallout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister1(pDeviceObj, &sCallout, &g_DriverContext->CalloutIdStream);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpsCalloutRegister1 (SNI) failed: 0x%08X\n", status));
        goto SkipSni;
    }

    filter.displayData.name = L"WFP SNI Block Filter";
    filter.displayData.description = L"Filter for SNI-based TLS blocking";
    filter.layerKey = FWPM_LAYER_STREAM_V4;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = GUID_MY_WFP_SNI_CALLOUT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0x0E;

    status = FwpmFilterAdd0(
        g_DriverContext->EngineHandle,
        &filter,
        NULL,
        &g_DriverContext->FilterIdStream
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpmFilterAdd0 (SNI) failed: 0x%08X\n", status));
        if (g_DriverContext->CalloutIdStream != 0) {
            FwpsCalloutUnregisterById0(g_DriverContext->CalloutIdStream);
            g_DriverContext->CalloutIdStream = 0;
        }
        goto SkipSni;
    }

    KdPrint(("WFP: SNI Stream filter registered\n"));

SkipSni:

    // ========================================================================
    // 3. QUIC 차단 Callout (DATAGRAM_DATA_V4)
    // ========================================================================

    RtlZeroMemory(&mCallout, sizeof(mCallout));
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    RtlZeroMemory(&filter, sizeof(filter));
    RtlZeroMemory(&filterConditions, sizeof(filterConditions));

    mCallout.calloutKey = GUID_MY_WFP_QUIC_CALLOUT;
    mCallout.displayData.name = L"WFP QUIC Block Callout";
    mCallout.displayData.description = L"Blocks QUIC (UDP 443) connections";
    mCallout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V4;

    status = FwpmCalloutAdd0(g_DriverContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpmCalloutAdd0 (QUIC) failed: 0x%08X\n", status));
        goto SkipQuic;
    }

    sCallout.calloutKey = GUID_MY_WFP_QUIC_CALLOUT;
    sCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN1)FilterClassifyQuic;
    sCallout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN1)FilterNotifyQuic;
    sCallout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister1(pDeviceObj, &sCallout, &g_DriverContext->CalloutIdQuic);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpsCalloutRegister1 (QUIC) failed: 0x%08X\n", status));
        goto SkipQuic;
    }

    // UDP 443 (QUIC) 필터 조건
    filterConditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    filterConditions[0].matchType = FWP_MATCH_EQUAL;
    filterConditions[0].conditionValue.type = FWP_UINT16;
    filterConditions[0].conditionValue.uint16 = 443;

    filter.displayData.name = L"WFP QUIC Block Filter";
    filter.displayData.description = L"Filter for QUIC (UDP 443) blocking";
    filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = GUID_MY_WFP_QUIC_CALLOUT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0x0D;
    filter.numFilterConditions = 1;
    filter.filterCondition = &filterConditions[0];

    status = FwpmFilterAdd0(
        g_DriverContext->EngineHandle,
        &filter,
        NULL,
        &g_DriverContext->FilterIdQuic
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpmFilterAdd0 (QUIC) failed: 0x%08X\n", status));
        if (g_DriverContext->CalloutIdQuic != 0) {
            FwpsCalloutUnregisterById0(g_DriverContext->CalloutIdQuic);
            g_DriverContext->CalloutIdQuic = 0;
        }
        goto SkipQuic;
    }

    KdPrint(("WFP: QUIC filter registered\n"));

SkipQuic:

    // ========================================================================
    // 4. DNS 모니터링 Callout (DATAGRAM_DATA_V4 - 인바운드)
    // ========================================================================

    RtlZeroMemory(&mCallout, sizeof(mCallout));
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    RtlZeroMemory(&filter, sizeof(filter));
    RtlZeroMemory(&filterConditions, sizeof(filterConditions));

    mCallout.calloutKey = GUID_MY_WFP_DNS_CALLOUT;
    mCallout.displayData.name = L"WFP DNS Monitor Callout";
    mCallout.displayData.description = L"Monitors DNS responses for IP caching";
    mCallout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V4;

    status = FwpmCalloutAdd0(g_DriverContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpmCalloutAdd0 (DNS) failed: 0x%08X\n", status));
        goto SkipDns;
    }

    sCallout.calloutKey = GUID_MY_WFP_DNS_CALLOUT;
    sCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN1)FilterClassifyDns;
    sCallout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN1)FilterNotifyDns;
    sCallout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister1(pDeviceObj, &sCallout, &g_DriverContext->CalloutIdDns);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpsCalloutRegister1 (DNS) failed: 0x%08X\n", status));
        goto SkipDns;
    }

    // DNS 응답 필터 (소스 포트 53)
    filterConditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    filterConditions[0].matchType = FWP_MATCH_EQUAL;
    filterConditions[0].conditionValue.type = FWP_UINT16;
    filterConditions[0].conditionValue.uint16 = 53;

    filter.displayData.name = L"WFP DNS Monitor Filter";
    filter.displayData.description = L"Filter for DNS response monitoring";
    filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;  // 검사만, 차단 안함
    filter.action.calloutKey = GUID_MY_WFP_DNS_CALLOUT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0x01;  // 낮은 우선순위
    filter.numFilterConditions = 1;
    filter.filterCondition = &filterConditions[0];

    status = FwpmFilterAdd0(
        g_DriverContext->EngineHandle,
        &filter,
        NULL,
        &g_DriverContext->FilterIdDns
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpmFilterAdd0 (DNS) failed: 0x%08X\n", status));
        if (g_DriverContext->CalloutIdDns != 0) {
            FwpsCalloutUnregisterById0(g_DriverContext->CalloutIdDns);
            g_DriverContext->CalloutIdDns = 0;
        }
        goto SkipDns;
    }

    KdPrint(("WFP: DNS monitor filter registered\n"));

SkipDns:
    KdPrint(("WFP: All filter registration completed\n"));
    return STATUS_SUCCESS;
}

void UnregisterWfpFilter(void)
{
    PAGED_CODE();

    if (g_DriverContext == NULL) {
        return;
    }

    if (g_DriverContext->EngineHandle != NULL) {
        // DNS 필터 제거
        if (g_DriverContext->FilterIdDns != 0) {
            FwpmFilterDeleteById0(g_DriverContext->EngineHandle, g_DriverContext->FilterIdDns);
            g_DriverContext->FilterIdDns = 0;
        }
        if (g_DriverContext->CalloutIdDns != 0) {
            FwpsCalloutUnregisterById0(g_DriverContext->CalloutIdDns);
            g_DriverContext->CalloutIdDns = 0;
        }

        // QUIC 필터 제거
        if (g_DriverContext->FilterIdQuic != 0) {
            FwpmFilterDeleteById0(g_DriverContext->EngineHandle, g_DriverContext->FilterIdQuic);
            g_DriverContext->FilterIdQuic = 0;
        }
        if (g_DriverContext->CalloutIdQuic != 0) {
            FwpsCalloutUnregisterById0(g_DriverContext->CalloutIdQuic);
            g_DriverContext->CalloutIdQuic = 0;
        }

        // SNI Stream 필터 제거
        if (g_DriverContext->FilterIdStream != 0) {
            FwpmFilterDeleteById0(g_DriverContext->EngineHandle, g_DriverContext->FilterIdStream);
            g_DriverContext->FilterIdStream = 0;
        }
        if (g_DriverContext->CalloutIdStream != 0) {
            FwpsCalloutUnregisterById0(g_DriverContext->CalloutIdStream);
            g_DriverContext->CalloutIdStream = 0;
        }

        // PID 필터 제거
        if (g_DriverContext->FilterIdConnect != 0) {
            FwpmFilterDeleteById0(g_DriverContext->EngineHandle, g_DriverContext->FilterIdConnect);
            g_DriverContext->FilterIdConnect = 0;
        }
        if (g_DriverContext->CalloutIdConnect != 0) {
            FwpsCalloutUnregisterById0(g_DriverContext->CalloutIdConnect);
            g_DriverContext->CalloutIdConnect = 0;
        }

        FwpmEngineClose0(g_DriverContext->EngineHandle);
        g_DriverContext->EngineHandle = NULL;
    }

    KdPrint(("WFP: Filter unregistration complete\n"));
}

// ============================================================================
// IRP 디스패치 루틴
// ============================================================================

NTSTATUS DispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp;
    ULONG ioControlCode;
    PVOID inputBuffer;
    PVOID outputBuffer;
    ULONG inputLength;
    ULONG outputLength;
    ULONG_PTR information = 0;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    if (g_DriverContext == NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Complete;
    }

    switch (ioControlCode) {
    case IOCTL_WFP_SET_BLOCK_PID:
    {
        PBLOCK_CONFIG pConfig = (PBLOCK_CONFIG)inputBuffer;

        if (pConfig == NULL || inputLength < sizeof(BLOCK_CONFIG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        g_DriverContext->BlockedPid = pConfig->ProcessId;
        KdPrint(("WFP: Block PID set to %lu\n", pConfig->ProcessId));
        break;
    }

    case IOCTL_WFP_RESET_BLOCK_PID:
        g_DriverContext->BlockedPid = 0;
        KdPrint(("WFP: Block PID reset\n"));
        break;

    case IOCTL_WFP_TOGGLE_CAPTURE:
    {
        PCAPTURE_TOGGLE pToggle = (PCAPTURE_TOGGLE)inputBuffer;

        if (pToggle == NULL || inputLength < sizeof(CAPTURE_TOGGLE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        g_DriverContext->CaptureEnabled = pToggle->Enable;
        KdPrint(("WFP: Capture %s\n", pToggle->Enable ? "enabled" : "disabled"));
        break;
    }

    case IOCTL_WFP_GET_PACKET_BATCH:
    {
        PPACKET_BATCH pBatch = (PPACKET_BATCH)outputBuffer;

        if (pBatch == NULL || outputLength < sizeof(PACKET_BATCH)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        DequeuePacketBatch(pBatch);
        information = sizeof(PACKET_BATCH);
        break;
    }

    case IOCTL_WFP_GET_CAPTURE_STATUS:
    {
        PCAPTURE_STATUS pStatus = (PCAPTURE_STATUS)outputBuffer;

        if (pStatus == NULL || outputLength < sizeof(CAPTURE_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(pStatus, sizeof(CAPTURE_STATUS));
        pStatus->IsCapturing = g_DriverContext->CaptureEnabled;
        pStatus->BlockedPid = g_DriverContext->BlockedPid;
        pStatus->QueuedPackets = g_DriverContext->PacketQueue ?
            (ULONG)g_DriverContext->PacketQueue->Count : 0;
        pStatus->TotalCaptured = (ULONG)g_DriverContext->TotalCaptured;
        pStatus->TotalBlocked = (ULONG)g_DriverContext->TotalBlocked;
        pStatus->DroppedPackets = (ULONG)g_DriverContext->DroppedPackets;
        pStatus->SniBlockingEnabled = g_DriverContext->SniBlockingEnabled;
        pStatus->SniBlockedUrls = g_DriverContext->SniBlockList ?
            (ULONG)g_DriverContext->SniBlockList->Count : 0;
        pStatus->SniTotalBlocked = (ULONG)(g_DriverContext->SniTotalBlocked +
            g_DriverContext->QuicTotalBlocked);

        information = sizeof(CAPTURE_STATUS);
        break;
    }

    case IOCTL_WFP_CLEAR_PACKET_QUEUE:
        ClearPacketQueueInternal();
        KdPrint(("WFP: Packet queue cleared\n"));
        break;

    case IOCTL_WFP_SNI_BLOCK_URL:
    {
        PSNI_BLOCK_REQUEST pRequest = (PSNI_BLOCK_REQUEST)inputBuffer;
        PSNI_BLOCK_RESPONSE pResponse = (PSNI_BLOCK_RESPONSE)outputBuffer;
        BOOLEAN result = FALSE;
        BOOLEAN isBlocked = FALSE;

        if (pRequest == NULL || inputLength < sizeof(SNI_BLOCK_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // NULL 종료 보장
        pRequest->Url[MAX_SNI_LENGTH - 1] = '\0';

        switch (pRequest->Action) {
        case SNI_ACTION_TOGGLE:
            result = ToggleSniUrl(pRequest->Url, &isBlocked);
            break;
        case SNI_ACTION_ADD:
            result = AddSniUrl(pRequest->Url);
            isBlocked = result;
            break;
        case SNI_ACTION_REMOVE:
            result = RemoveSniUrl(pRequest->Url);
            isBlocked = FALSE;
            break;
        default:
            result = FALSE;
            break;
        }

        if (pResponse != NULL && outputLength >= sizeof(SNI_BLOCK_RESPONSE)) {
            RtlZeroMemory(pResponse, sizeof(SNI_BLOCK_RESPONSE));
            pResponse->Success = result ? 1 : 0;
            pResponse->IsBlocked = isBlocked ? 1 : 0;
            pResponse->TotalBlockedUrls = g_DriverContext->SniBlockList ?
                (ULONG)g_DriverContext->SniBlockList->Count : 0;
            information = sizeof(SNI_BLOCK_RESPONSE);
        }
        break;
    }

    case IOCTL_WFP_SNI_GET_BLOCK_LIST:
    {
        PSNI_LIST_REQUEST pRequest = (PSNI_LIST_REQUEST)inputBuffer;
        PSNI_LIST_RESPONSE pResponse = (PSNI_LIST_RESPONSE)outputBuffer;
        PSNI_BLOCK_LIST list;
        ULONG startIndex = 0;
        ULONG maxCount = SNI_BLOCK_LIST_SIZE;
        ULONG returnedCount = 0;
        ULONG totalInUse = 0;

        if (pResponse == NULL || outputLength < sizeof(SNI_LIST_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(pResponse, sizeof(SNI_LIST_RESPONSE));

        if (pRequest != NULL && inputLength >= sizeof(SNI_LIST_REQUEST)) {
            startIndex = pRequest->StartIndex;
            if (pRequest->MaxCount > 0 && pRequest->MaxCount <= SNI_BLOCK_LIST_SIZE) {
                maxCount = pRequest->MaxCount;
            }
        }

        list = g_DriverContext->SniBlockList;
        if (list != NULL) {
            KLOCK_QUEUE_HANDLE lockHandle;
            ULONG currentIndex = 0;

            KeAcquireInStackQueuedSpinLock(&list->Lock, &lockHandle);

            // 전체 개수 및 요청 범위 엔트리 복사
            for (LONG i = 0; i < MAX_BLOCKED_URLS; i++) {
                if (list->Entries[i].InUse && list->Entries[i].Url[0] != '\0') {
                    totalInUse++;

                    if (currentIndex >= startIndex && returnedCount < maxCount) {
                        // URL 복사 (null 종료 보장)
                        RtlZeroMemory(&pResponse->Entries[returnedCount], sizeof(SNI_URL_ENTRY));
                        RtlStringCchCopyA(pResponse->Entries[returnedCount].Url,
                            MAX_SNI_LENGTH,
                            list->Entries[i].Url);
                        pResponse->Entries[returnedCount].BlockCount =
                            (ULONG)list->Entries[i].BlockCount;

                        KdPrint(("WFP SNI List: [%lu] '%s' (blocked %lu times)\n",
                            returnedCount,
                            pResponse->Entries[returnedCount].Url,
                            pResponse->Entries[returnedCount].BlockCount));

                        returnedCount++;
                    }
                    currentIndex++;
                }
            }

            KeReleaseInStackQueuedSpinLock(&lockHandle);
        }

        pResponse->TotalCount = totalInUse;
        pResponse->ReturnedCount = returnedCount;
        pResponse->StartIndex = startIndex;

        KdPrint(("WFP SNI: GetBlockList returned %lu of %lu URLs (start=%lu)\n",
            returnedCount, totalInUse, startIndex));

        information = sizeof(SNI_LIST_RESPONSE);
        break;
    }

    case IOCTL_WFP_SNI_CLEAR_BLOCK_LIST:
        ClearSniBlockList();
        KdPrint(("WFP SNI: Block list cleared\n"));
        break;

    case IOCTL_WFP_SNI_TOGGLE_BLOCKING:
    {
        PSNI_TOGGLE pToggle = (PSNI_TOGGLE)inputBuffer;

        if (pToggle == NULL || inputLength < sizeof(SNI_TOGGLE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        g_DriverContext->SniBlockingEnabled = pToggle->Enable;
        g_DriverContext->QuicBlockingEnabled = pToggle->Enable;
        g_DriverContext->DnsMonitoringEnabled = pToggle->Enable;

        KdPrint(("WFP SNI: All blocking %s\n", pToggle->Enable ? "enabled" : "disabled"));
        break;
    }

    // ========================================================================
    // DNS 싱크홀 IOCTL 
    // ========================================================================
    case IOCTL_WFP_DNS_SINKHOLE_TOGGLE:
    {
        PDNS_SINKHOLE_TOGGLE pToggle = (PDNS_SINKHOLE_TOGGLE)inputBuffer;

        if (pToggle == NULL || inputLength < sizeof(DNS_SINKHOLE_TOGGLE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        g_DriverContext->DnsSinkholeEnabled = pToggle->Enable;
        KdPrint(("WFP DNS Sinkhole: %s\n", pToggle->Enable ? "enabled" : "disabled"));
        break;
    }

    case IOCTL_WFP_DNS_SINKHOLE_SET_IP:
    {
        PDNS_SINKHOLE_CONFIG pConfig = (PDNS_SINKHOLE_CONFIG)inputBuffer;
        KIRQL oldIrql;

        if (pConfig == NULL || inputLength < sizeof(DNS_SINKHOLE_CONFIG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KeAcquireSpinLock(&g_DriverContext->DnsSinkholeLock, &oldIrql);
        g_DriverContext->SinkholeIp = pConfig->SinkholeIp;
        g_DriverContext->SinkholeHttpPort = pConfig->HttpPort;
        g_DriverContext->SinkholeHttpsPort = pConfig->HttpsPort;
        KeReleaseSpinLock(&g_DriverContext->DnsSinkholeLock, oldIrql);

        KdPrint(("WFP DNS Sinkhole: IP set to %u.%u.%u.%u, HTTP:%u, HTTPS:%u\n",
            (pConfig->SinkholeIp >> 24) & 0xFF,
            (pConfig->SinkholeIp >> 16) & 0xFF,
            (pConfig->SinkholeIp >> 8) & 0xFF,
            pConfig->SinkholeIp & 0xFF,
            pConfig->HttpPort, pConfig->HttpsPort));
        break;
    }

    case IOCTL_WFP_DNS_SINKHOLE_GET_STATUS:
    {
        PDNS_SINKHOLE_STATUS pStatus = (PDNS_SINKHOLE_STATUS)outputBuffer;
        KIRQL oldIrql;

        if (pStatus == NULL || outputLength < sizeof(DNS_SINKHOLE_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(pStatus, sizeof(DNS_SINKHOLE_STATUS));

        KeAcquireSpinLock(&g_DriverContext->DnsSinkholeLock, &oldIrql);
        pStatus->Enabled = g_DriverContext->DnsSinkholeEnabled;
        pStatus->SinkholeIp = g_DriverContext->SinkholeIp;
        pStatus->HttpPort = g_DriverContext->SinkholeHttpPort;
        pStatus->HttpsPort = g_DriverContext->SinkholeHttpsPort;
        KeReleaseSpinLock(&g_DriverContext->DnsSinkholeLock, oldIrql);

        pStatus->TotalRedirected = (ULONGLONG)g_DriverContext->TotalSinkholeRedirected;
        pStatus->TotalDnsModified = (ULONGLONG)g_DriverContext->TotalDnsModified;

        information = sizeof(DNS_SINKHOLE_STATUS);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

// ============================================================================
// 드라이버 언로드
// ============================================================================

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;

    PAGED_CODE();

    KdPrint(("WFP: Driver unloading...\n"));

    UnregisterWfpFilter();
    CleanupPacketQueue();
    CleanupSniBlockList();
    CleanupIpCache();

    if (g_DriverContext != NULL) {
        ExFreePoolWithTag(g_DriverContext, 'TCFW');
        g_DriverContext = NULL;
    }

    RtlInitUnicodeString(&symLink, SYMBOLIC_LINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    KdPrint(("WFP: Driver unloaded\n"));
}

// ============================================================================
// 드라이버 엔트리
// ============================================================================

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING devName;
    UNICODE_STRING symLink;
    PDEVICE_OBJECT deviceObject = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("WFP: Driver loading (Ultimate SNI/QUIC blocking)...\n"));

    g_DriverContext = (PDRIVER_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(DRIVER_CONTEXT),
        'TCFW'
    );

    if (g_DriverContext == NULL) {
        KdPrint(("WFP: Failed to allocate driver context\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_DriverContext, sizeof(DRIVER_CONTEXT));

    // 모든 차단 기능 기본 활성화
    g_DriverContext->SniBlockingEnabled = 1;
    g_DriverContext->QuicBlockingEnabled = 1;
    g_DriverContext->DnsMonitoringEnabled = 1;

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symLink, SYMBOLIC_LINK_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: IoCreateDevice failed: 0x%08X\n", status));
        goto Cleanup;
    }

    g_DeviceObject = deviceObject;

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: IoCreateSymbolicLink failed: 0x%08X\n", status));
        goto Cleanup;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    status = InitializePacketQueue();
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: InitializePacketQueue failed: 0x%08X\n", status));
        goto Cleanup;
    }

    status = InitializeSniBlockList();
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: InitializeSniBlockList failed: 0x%08X\n", status));
        goto Cleanup;
    }

    status = InitializeIpCache();
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: InitializeIpCache failed: 0x%08X\n", status));
        goto Cleanup;
    }

    status = InitializeDnsSinkhole();
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: InitializeDnsSinkhole failed: 0x%08X\n", status));
        goto Cleanup;
    }

    status = RegisterWfpFilter(deviceObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: RegisterWfpFilter failed: 0x%08X\n", status));
        goto Cleanup;
    }

    KdPrint(("WFP: Driver loaded successfully (SNI + QUIC + DNS blocking)\n"));
    return STATUS_SUCCESS;

Cleanup:
    if (g_DriverContext != NULL) {
        CleanupPacketQueue();
        CleanupSniBlockList();
        CleanupIpCache();
        ExFreePoolWithTag(g_DriverContext, 'TCFW');
        g_DriverContext = NULL;
    }

    if (deviceObject != NULL) {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(deviceObject);
    }

    return status;
}
