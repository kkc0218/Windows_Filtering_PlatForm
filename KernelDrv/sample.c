#include <ntddk.h>
#include <ndis.h>
#include <initguid.h>
#include <fwpmk.h>
#include <fwpsk.h>

#include "Shared.h"

#pragma comment(lib, "fwpkclnt.lib")
#pragma comment(lib, "ndis.lib")

//전방 선언
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
void DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS RegisterWfpFilter(PDEVICE_OBJECT pDeviceObj);


void NTAPI FilterClassify(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,      // FN1에서 추가된 중요 인자
    const FWPS_FILTER1* filter,           // FILTER0 -> FILTER1
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI FilterNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter               // FILTER0 -> FILTER1
);

// --- 메모리 섹션 설정 ---
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, DispatchDeviceControl)

// 전역 변수 (Non-Paged 영역)
#pragma data_seg(".nonpaged")
volatile ULONG g_BlockedPid = 0;
HANDLE g_EngineHandle = NULL;
UINT32 g_CalloutId = 0;
UINT64 g_FilterId = 0;
#pragma data_seg()

// --- [핵심 로직: FilterClassify] ---
#pragma code_seg(".text")

//WIN10, 11에서 제공되는 Filtering Function
void NTAPI FilterClassify(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER1* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
)
{

    
    if (classifyOut == NULL || !MmIsAddressValid(classifyOut)) {
        return;
    }

    // 기본값 허용 설정
    classifyOut->actionType = FWP_ACTION_PERMIT;

    // 메타데이터 유효성 검사
    if (inMetaValues == NULL || !MmIsAddressValid((PVOID)(inMetaValues))) {
        return;
    }

    // 차단할 PID가 설정되어 있는지 확인
    ULONG targetPid = g_BlockedPid;
    if (targetPid == 0) return;

    // BSOD 방지 : PID 필드 존재 여부 확인 후 차단 로직 실행
    // PID가 없는 패킷도 존재할 수 있음
    if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0)
    {
        if (inMetaValues->processId == (UINT64)targetPid)
        {
            classifyOut->actionType = FWP_ACTION_BLOCK;

            // 쓰기 권한이 있는 경우에만 수정
            if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            }
        }
    }

    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
}

NTSTATUS NTAPI FilterNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}
#pragma code_seg()

// 등록 및 I/O 로직-

NTSTATUS RegisterWfpFilter(PDEVICE_OBJECT pDeviceObj) {
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SESSION0 session = { 0 };
    FWPM_CALLOUT0 mCallout = { 0 };
    FWPS_CALLOUT1 sCallout = { 0 };
    FWPM_FILTER0 filter = { 0 };

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) return status;

    mCallout.calloutKey = GUID_MY_WFP_CALLOUT;
    mCallout.displayData.name = L"My Block Callout";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) return status;

    sCallout.calloutKey = GUID_MY_WFP_CALLOUT;
    // FN1으로 캐스팅하여 등록
    sCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN1)FilterClassify;
    sCallout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN1)FilterNotify;

    // FwpsCalloutRegister1 사용 (Win10 표준)
    status = FwpsCalloutRegister1(pDeviceObj, &sCallout, &g_CalloutId);
    if (!NT_SUCCESS(status)) return status;

    filter.displayData.name = L"My Block Filter";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = GUID_MY_WFP_CALLOUT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;

    status = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterId);
    return status;
}


// EXE : PID 송신 => Kernel System Driver : 후처리 
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;


    //응용 프로그램이 DeviceIoControl을 호출한 경우
    //간편성을 위해서 우선 IOCTL_WFP_SET_BLOCK_PID만을 지정함

    if (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        if (irpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_WFP_SET_BLOCK_PID) {
            PBLOCK_CONFIG pConfig = (PBLOCK_CONFIG)Irp->AssociatedIrp.SystemBuffer;
            if (pConfig && irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(BLOCK_CONFIG)) {
                g_BlockedPid = pConfig->ProcessId;
            }
            else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
        }
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SYMBOLIC_LINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (g_EngineHandle) {
        if (g_FilterId) FwpmFilterDeleteById0(g_EngineHandle, g_FilterId);
        if (g_CalloutId) FwpsCalloutUnregisterById0(g_CalloutId);
        FwpmEngineClose0(g_EngineHandle);
    }

    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING devName, symLink;

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symLink, SYMBOLIC_LINK_NAME);

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = DispatchDeviceControl;
    }
    DriverObject->DriverUnload = DriverUnload;

    status = RegisterWfpFilter(deviceObject);
    if (!NT_SUCCESS(status)) {
        DriverUnload(DriverObject);
        return status;
    }

    return STATUS_SUCCESS;
}
