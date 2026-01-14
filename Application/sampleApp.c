#include <iostream>
#include <windows.h>
#include <winioctl.h>
#include "..\common\Shared.h"
// 사용자 모드에서는 심볼릭 링크 앞에 \\.\ 을 붙여야 함.
#define USER_MODE_DEVICE_NAME L"\\\\.\\WfpExampleLink"

int main() {
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    BLOCK_CONFIG config = { 0 };
    DWORD bytesReturned = 0;
    unsigned long targetPid = 0;

    std::cout << "--- WFP PID Blocker Controller ---" << std::endl;

    // 1. 드라이버 핸들 열기
    hDevice = CreateFile(
        USER_MODE_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] 드라이버 핸들을 얻지 못했습니다. (에러 코드: " << GetLastError() << ")" << std::endl;
        std::cout << "[!] 드라이버가 로드되어 있는지, 관리자 권한으로 실행 중인지 확인하세요." << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "[+] 드라이버와 연결되었습니다." << std::endl;

    while (true) {
        std::cout << "\n차단할 PID 입력 (종료: 0): ";
        if (!(std::cin >> targetPid)) {
            std::cin.clear();
            std::cin.ignore(INT_MAX, '\n');
            continue;
        }

        if (targetPid == 0) break;

        config.ProcessId = targetPid;

        // 2. IOCTL을 통해 드라이버에 PID 전달
        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_WFP_SET_BLOCK_PID,
            &config,
            sizeof(config),
            NULL,
            0,
            &bytesReturned,
            NULL
        );

        if (success) {
            std::cout << "[+] 성공: PID " << targetPid << " 의 네트워크가 차단되었습니다." << std::endl;
        }
        else {
            std::cerr << "[-] 실패: 드라이버 통신 오류 (에러 코드: " << GetLastError() << ")" << std::endl;
        }
    }

    CloseHandle(hDevice);
    return 0;
}
