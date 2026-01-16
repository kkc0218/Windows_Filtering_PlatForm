// ============================================================================
// sample.c - WFP Packet Filtering & Capture Kernel Driver
// ============================================================================
// Windows Filtering Platform 기반 패킷 필터링 및 캡처 드라이버
// - PID 기반 네트워크 차단
// - 실시간 패킷 캡처 및 메타데이터 수집
// - 링 버퍼 기반 패킷 큐
// - KSPIN_LOCK 기반 동기화
// ============================================================================

// 헤더 충돌 방지를 위한 순서 지정
#include <ntddk.h>
#include <ndis.h>

// WFP 헤더
#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union
#include <initguid.h>
#include <fwpmk.h>
#include <fwpsk.h>
#pragma warning(pop)

// 공용 헤더
#define __KERNEL_MODE__
#include "Shared.h"

// 라이브러리 링크
#pragma comment(lib, "fwpkclnt.lib")
#pragma comment(lib, "ndis.lib")

// ============================================================================
// 전방 선언 (DRIVER_INITIALIZE 등 매크로 사용하지 않고 직접 선언)
// ============================================================================
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

NTSTATUS DispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS RegisterWfpFilter(_In_ PDEVICE_OBJECT pDeviceObj);
void UnregisterWfpFilter(void);

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
// 내부 데이터 구조체 (Non-Paged)
// ============================================================================

// 패킷 큐 엔트리
typedef struct _PACKET_QUEUE_ENTRY {
    PACKET_INFO Info;
} PACKET_QUEUE_ENTRY, * PPACKET_QUEUE_ENTRY;

// 패킷 링 버퍼
typedef struct _PACKET_RING_BUFFER {
    PACKET_QUEUE_ENTRY Entries[PACKET_QUEUE_SIZE];
    volatile LONG Head;         // 다음 쓰기 위치
    volatile LONG Tail;         // 다음 읽기 위치
    volatile LONG Count;        // 현재 항목 수
    KSPIN_LOCK Lock;            // 동기화 락
} PACKET_RING_BUFFER, * PPACKET_RING_BUFFER;

// 드라이버 상태 구조체
typedef struct _DRIVER_CONTEXT {
    // WFP 관련
    HANDLE EngineHandle;
    UINT32 CalloutIdConnect;
    UINT64 FilterIdConnect;

    // 설정
    volatile ULONG BlockedPid;
    volatile ULONG CaptureEnabled;

    // 통계
    volatile LONG64 TotalCaptured;
    volatile LONG64 TotalBlocked;
    volatile LONG64 DroppedPackets;

    // 패킷 큐
    PPACKET_RING_BUFFER PacketQueue;

    // 배치 시퀀스 번호
    volatile LONG BatchSequence;

} DRIVER_CONTEXT, * PDRIVER_CONTEXT;

// ============================================================================
// 전역 변수 (Non-Paged 영역)
// ============================================================================
static PDRIVER_CONTEXT g_DriverContext = NULL;
static PDEVICE_OBJECT g_DeviceObject = NULL;

// ============================================================================
// 유틸리티 함수 (Non-Paged)
// ============================================================================

// 링 버퍼 초기화
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS InitializePacketQueue(void)
{
    if (g_DriverContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Non-Paged Pool에서 할당
    g_DriverContext->PacketQueue = (PPACKET_RING_BUFFER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(PACKET_RING_BUFFER),
        'QPFW'  // Tag: 'WFPQ' (역순)
    );

    if (g_DriverContext->PacketQueue == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_DriverContext->PacketQueue, sizeof(PACKET_RING_BUFFER));
    KeInitializeSpinLock(&g_DriverContext->PacketQueue->Lock);

    return STATUS_SUCCESS;
}

// 링 버퍼 정리
_IRQL_requires_max_(APC_LEVEL)
void CleanupPacketQueue(void)
{
    if (g_DriverContext != NULL && g_DriverContext->PacketQueue != NULL) {
        ExFreePoolWithTag(g_DriverContext->PacketQueue, 'QPFW');
        g_DriverContext->PacketQueue = NULL;
    }
}

// 패킷 큐에 추가 (DISPATCH_LEVEL에서 호출 가능)
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN EnqueuePacket(_In_ const PACKET_INFO* pPacket)
{
    BOOLEAN result = FALSE;
    KLOCK_QUEUE_HANDLE lockHandle;
    PPACKET_RING_BUFFER queue;

    if (g_DriverContext == NULL || g_DriverContext->PacketQueue == NULL || pPacket == NULL) {
        return FALSE;
    }

    queue = g_DriverContext->PacketQueue;

    // InStackQueuedSpinLock 사용 (고성능)
    KeAcquireInStackQueuedSpinLock(&queue->Lock, &lockHandle);

    // 큐가 가득 찼는지 확인
    if (queue->Count < PACKET_QUEUE_SIZE) {
        // 패킷 복사
        LONG head = queue->Head;
        RtlCopyMemory(&queue->Entries[head].Info, pPacket, sizeof(PACKET_INFO));

        // Head 포인터 이동 (링 버퍼)
        queue->Head = (head + 1) % PACKET_QUEUE_SIZE;
        InterlockedIncrement(&queue->Count);

        result = TRUE;
    }
    else {
        // 큐 오버플로우 - 패킷 드롭
        InterlockedIncrement64(&g_DriverContext->DroppedPackets);
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    return result;
}

// 패킷 배치 추출 (PASSIVE_LEVEL/APC_LEVEL에서 호출)
_IRQL_requires_max_(APC_LEVEL)
ULONG DequeuePacketBatch(_Out_ PACKET_BATCH* pBatch)
{
    ULONG count = 0;
    KLOCK_QUEUE_HANDLE lockHandle;
    PPACKET_RING_BUFFER queue;
    KIRQL oldIrql;

    if (g_DriverContext == NULL || g_DriverContext->PacketQueue == NULL || pBatch == NULL) {
        return 0;
    }

    RtlZeroMemory(pBatch, sizeof(PACKET_BATCH));
    queue = g_DriverContext->PacketQueue;

    // IRQL을 DISPATCH_LEVEL로 올려서 스핀락 획득
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    KeAcquireInStackQueuedSpinLock(&queue->Lock, &lockHandle);

    // 배치 크기만큼 또는 큐에 있는 만큼 추출
    while (count < MAX_PACKETS_PER_BATCH && queue->Count > 0) {
        LONG tail = queue->Tail;

        // 패킷 복사
        RtlCopyMemory(&pBatch->Packets[count], &queue->Entries[tail].Info, sizeof(PACKET_INFO));

        // Tail 포인터 이동
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

// 패킷 큐 클리어
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

// 현재 시스템 시간 가져오기
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
// WFP Classify 콜백 (Non-Paged, DISPATCH_LEVEL에서 호출됨)
// ============================================================================

void NTAPI FilterClassifyConnect(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    PACKET_INFO packetInfo = { 0 };
    BOOLEAN shouldBlock = FALSE;
    BOOLEAN shouldCapture = FALSE;
    ULONG targetPid = 0;
    UINT64 processPid = 0;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // 출력 파라미터 유효성 검사
    if (classifyOut == NULL || !MmIsAddressValid((PVOID)classifyOut)) {
        return;
    }

    // 기본값: 허용
    classifyOut->actionType = FWP_ACTION_PERMIT;

    // 드라이버 컨텍스트 유효성 검사
    if (g_DriverContext == NULL) {
        return;
    }

    // 메타데이터 유효성 검사
    if (inMetaValues == NULL || !MmIsAddressValid((PVOID)inMetaValues)) {
        return;
    }

    // 고정값 유효성 검사
    if (inFixedValues == NULL || !MmIsAddressValid((PVOID)inFixedValues)) {
        return;
    }

    // 캡처 및 차단 설정 확인
    targetPid = g_DriverContext->BlockedPid;
    shouldCapture = (g_DriverContext->CaptureEnabled != 0);

    // PID 확인 (메타데이터에 PID가 있는 경우에만)
    if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0) {
        processPid = inMetaValues->processId;

        // 차단 대상 PID인지 확인
        if (targetPid != 0 && processPid == (UINT64)targetPid) {
            shouldBlock = TRUE;
        }
    }

    // 캡처가 활성화된 경우 패킷 정보 수집
    if (shouldCapture || shouldBlock) {
        // 타임스탬프
        packetInfo.Timestamp = GetCurrentTimestamp();

        // PID
        packetInfo.ProcessId = (ULONG)processPid;

        // 방향 (ALE_AUTH_CONNECT는 항상 Outbound)
        packetInfo.Direction = PACKET_DIR_OUTBOUND;

        // IP 주소 추출 (인덱스는 레이어에 따라 다름)
        // FWPM_LAYER_ALE_AUTH_CONNECT_V4 레이어의 필드 인덱스
        if (inFixedValues->incomingValue != NULL) {
            // Local IP (인덱스 0)
            if (inFixedValues->valueCount > FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS) {
                packetInfo.LocalAddress = inFixedValues->incomingValue[
                    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
            }

            // Remote IP (인덱스 1)
            if (inFixedValues->valueCount > FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS) {
                packetInfo.RemoteAddress = inFixedValues->incomingValue[
                    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
            }

            // Local Port (인덱스 2)
            if (inFixedValues->valueCount > FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT) {
                packetInfo.LocalPort = inFixedValues->incomingValue[
                    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
            }

            // Remote Port (인덱스 3)
            if (inFixedValues->valueCount > FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT) {
                packetInfo.RemotePort = inFixedValues->incomingValue[
                    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
            }

            // Protocol (인덱스 4)
            if (inFixedValues->valueCount > FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL) {
                packetInfo.Protocol = inFixedValues->incomingValue[
                    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
            }
        }

        // 패킷 크기 (메타데이터에서)
        if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE) != 0) {
            packetInfo.PacketSize = inMetaValues->transportHeaderSize;
        }

        // 액션 설정
        packetInfo.Action = shouldBlock ? PACKET_ACTION_BLOCK : PACKET_ACTION_PERMIT;

        // 캡처가 활성화된 경우 큐에 추가
        if (shouldCapture) {
            EnqueuePacket(&packetInfo);
            InterlockedIncrement64(&g_DriverContext->TotalCaptured);
        }
    }

    // 차단 처리
    if (shouldBlock) {
        classifyOut->actionType = FWP_ACTION_BLOCK;

        // 쓰기 권한 제거 (다른 필터가 덮어쓰지 못하게)
        if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }

        InterlockedIncrement64(&g_DriverContext->TotalBlocked);
    }
}

NTSTATUS NTAPI FilterNotifyConnect(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter
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

    PAGED_CODE();

    if (g_DriverContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 세션 설정 (동적 - 드라이버 언로드 시 자동 정리)
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    // WFP 엔진 열기
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

    // Management Callout 등록 (ALE_AUTH_CONNECT_V4)
    mCallout.calloutKey = GUID_MY_WFP_CALLOUT;
    mCallout.displayData.name = L"WFP PID Block Callout";
    mCallout.displayData.description = L"Blocks network connections for specified PID";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    status = FwpmCalloutAdd0(g_DriverContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpmCalloutAdd0 failed: 0x%08X\n", status));
        return status;
    }

    // System Callout 등록
    sCallout.calloutKey = GUID_MY_WFP_CALLOUT;
    sCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN1)FilterClassifyConnect;
    sCallout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN1)FilterNotifyConnect;
    sCallout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister1(pDeviceObj, &sCallout, &g_DriverContext->CalloutIdConnect);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpsCalloutRegister1 failed: 0x%08X\n", status));
        return status;
    }

    // 필터 등록
    filter.displayData.name = L"WFP PID Block Filter";
    filter.displayData.description = L"Filter for PID-based connection blocking";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = GUID_MY_WFP_CALLOUT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0x0F;  // 높은 우선순위

    status = FwpmFilterAdd0(
        g_DriverContext->EngineHandle,
        &filter,
        NULL,
        &g_DriverContext->FilterIdConnect
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: FwpmFilterAdd0 failed: 0x%08X\n", status));
        return status;
    }

    KdPrint(("WFP: Filter registration successful\n"));
    return STATUS_SUCCESS;
}

void UnregisterWfpFilter(void)
{
    PAGED_CODE();

    if (g_DriverContext == NULL) {
        return;
    }

    if (g_DriverContext->EngineHandle != NULL) {
        // 필터 제거
        if (g_DriverContext->FilterIdConnect != 0) {
            FwpmFilterDeleteById0(g_DriverContext->EngineHandle, g_DriverContext->FilterIdConnect);
            g_DriverContext->FilterIdConnect = 0;
        }

        // Callout 해제
        if (g_DriverContext->CalloutIdConnect != 0) {
            FwpsCalloutUnregisterById0(g_DriverContext->CalloutIdConnect);
            g_DriverContext->CalloutIdConnect = 0;
        }

        // 엔진 닫기
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

    // 드라이버 컨텍스트 확인
    if (g_DriverContext == NULL) {
        status = STATUS_DEVICE_NOT_READY;
        goto Complete;
    }

    switch (ioControlCode) {

        // PID 차단 설정
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

    // PID 차단 해제
    case IOCTL_WFP_RESET_BLOCK_PID:
    {
        g_DriverContext->BlockedPid = 0;
        KdPrint(("WFP: Block PID reset\n"));
        break;
    }

    // 캡처 토글
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

    // 패킷 배치 조회
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

    // 캡처 상태 조회
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
        pStatus->TotalCaptured = (ULONG)g_DriverContext->TotalCaptured;
        pStatus->TotalBlocked = (ULONG)g_DriverContext->TotalBlocked;
        pStatus->DroppedPackets = (ULONG)g_DriverContext->DroppedPackets;

        if (g_DriverContext->PacketQueue != NULL) {
            pStatus->QueuedPackets = (ULONG)g_DriverContext->PacketQueue->Count;
        }

        information = sizeof(CAPTURE_STATUS);
        break;
    }

    // 패킷 큐 초기화
    case IOCTL_WFP_CLEAR_PACKET_QUEUE:
    {
        ClearPacketQueueInternal();
        KdPrint(("WFP: Packet queue cleared\n"));
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

    // WFP 필터 해제
    UnregisterWfpFilter();

    // 패킷 큐 정리
    CleanupPacketQueue();

    // 드라이버 컨텍스트 정리
    if (g_DriverContext != NULL) {
        ExFreePoolWithTag(g_DriverContext, 'TCFW');
        g_DriverContext = NULL;
    }

    // 심볼릭 링크 삭제
    RtlInitUnicodeString(&symLink, SYMBOLIC_LINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    // 디바이스 객체 삭제
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

    KdPrint(("WFP: Driver loading...\n"));

    // 드라이버 컨텍스트 할당 (Non-Paged Pool)
    g_DriverContext = (PDRIVER_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(DRIVER_CONTEXT),
        'TCFW'  // Tag: 'WFCT' (역순)
    );

    if (g_DriverContext == NULL) {
        KdPrint(("WFP: Failed to allocate driver context\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_DriverContext, sizeof(DRIVER_CONTEXT));

    // 디바이스 이름 초기화
    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symLink, SYMBOLIC_LINK_NAME);

    // 디바이스 객체 생성
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

    // 심볼릭 링크 생성
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: IoCreateSymbolicLink failed: 0x%08X\n", status));
        goto Cleanup;
    }

    // 디스패치 루틴 설정
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // 패킷 큐 초기화
    status = InitializePacketQueue();
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: InitializePacketQueue failed: 0x%08X\n", status));
        goto Cleanup;
    }

    // WFP 필터 등록
    status = RegisterWfpFilter(deviceObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: RegisterWfpFilter failed: 0x%08X\n", status));
        goto Cleanup;
    }

    KdPrint(("WFP: Driver loaded successfully\n"));
    return STATUS_SUCCESS;

Cleanup:
    // 실패 시 정리
    if (g_DriverContext != NULL) {
        CleanupPacketQueue();
        ExFreePoolWithTag(g_DriverContext, 'TCFW');
        g_DriverContext = NULL;
    }

    if (deviceObject != NULL) {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(deviceObject);
    }

    return status;
}
