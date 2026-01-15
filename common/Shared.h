#pragma once
#include <devioctl.h>
#include <guiddef.h>

#define DEVICE_NAME         L"\\Device\\WfpExampleDevice"
#define SYMBOLIC_LINK_NAME  L"\\??\\WfpExampleLink"

// GUID 정의 방식 변경 (선언만 수행)
// {B180900E-B939-4E64-912A-63799634B03B}
#ifndef GUID_MY_WFP_CALLOUT_DEFINED
#define GUID_MY_WFP_CALLOUT_DEFINED
DEFINE_GUID(GUID_MY_WFP_CALLOUT,
    0xb180900e, 0xb939, 0x4e64, 0x91, 0x2a, 0x63, 0x79, 0x96, 0x34, 0xb0, 0x3b);
#endif

#define IOCTL_WFP_SET_BLOCK_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _BLOCK_CONFIG {
    unsigned long ProcessId;
} BLOCK_CONFIG, * PBLOCK_CONFIG;
