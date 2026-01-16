// ============================================================================
// EX_FilterDrvApp.cpp - WFP Packet Filtering & Capture Application
// ============================================================================
// User Mode 응용프로그램
// - 이벤트 기반 메인 루프
// - 멀티스레딩 패킷 캡처
// - 배치 처리를 통한 성능 최적화
// ============================================================================

// Windows 헤더 충돌 방지를 위한 순서 지정
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
#include <process.h>

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <fstream>
#include <queue>
#include <mutex>
#include <atomic>
#include <chrono>
#include <ctime>
#include <io.h>
#include <fcntl.h>
#include <locale.h>

#pragma comment(lib, "ws2_32.lib")

// 공용 헤더 포함
#include "..\common\Shared.h"

// ============================================================================
// 상수 정의
// ============================================================================
#define USER_MODE_DEVICE_NAME L"\\\\.\\WfpExampleLink"
#define LOG_FILE_NAME "packet_capture.log"
#define CAPTURE_POLL_INTERVAL_MS 100    // 패킷 폴링 간격 (ms)
#define UI_REFRESH_INTERVAL_MS 1000     // UI 상태 갱신 간격 (ms)

// ============================================================================
// 전역 변수
// ============================================================================
static HANDLE g_hDevice = INVALID_HANDLE_VALUE;     // 드라이버 핸들
static HANDLE g_hCaptureThread = NULL;              // 캡처 스레드 핸들
static HANDLE g_hStopEvent = NULL;                  // 스레드 종료 이벤트

static std::atomic<bool> g_bRunning(true);          // 프로그램 실행 상태
static std::atomic<bool> g_bCapturing(false);       // 캡처 상태
static std::atomic<unsigned long> g_ulBlockedPid(0); // 차단 중인 PID

static std::mutex g_logMutex;                       // 로그 파일 동기화
static std::ofstream g_logFile;                     // 로그 파일 스트림

// 통계
static std::atomic<unsigned long long> g_ullTotalCaptured(0);
static std::atomic<unsigned long long> g_ullTotalBlocked(0);

// ============================================================================
// 유틸리티 함수
// ============================================================================

// 현재 시간 문자열 반환
std::string GetCurrentTimeString() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    struct tm timeinfo;
    localtime_s(&timeinfo, &time);

    std::ostringstream oss;
    oss << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

// FILETIME을 문자열로 변환
std::string FileTimeToString(unsigned __int64 timestamp) {
    FILETIME ft;
    SYSTEMTIME st;
    ft.dwLowDateTime = (DWORD)(timestamp & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(timestamp >> 32);
    FileTimeToSystemTime(&ft, &st);

    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(4) << st.wYear << "-"
        << std::setw(2) << st.wMonth << "-"
        << std::setw(2) << st.wDay << " "
        << std::setw(2) << st.wHour << ":"
        << std::setw(2) << st.wMinute << ":"
        << std::setw(2) << st.wSecond << "."
        << std::setw(3) << st.wMilliseconds;
    return oss.str();
}

// IP 주소를 문자열로 변환 (WFP 호스트 바이트 순서)
std::string IpToString(unsigned long ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << ((ip >> 0) & 0xFF);
    return oss.str();
}

// 프로토콜을 문자열로 변환
const char* ProtocolToString(unsigned char protocol) {
    switch (protocol) {
    case PROTO_TCP:  return "TCP";
    case PROTO_UDP:  return "UDP";
    case PROTO_ICMP: return "ICMP";
    default:         return "OTHER";
    }
}

// 방향을 문자열로 변환
const char* DirectionToString(unsigned char direction) {
    return (direction == PACKET_DIR_OUTBOUND) ? "OUT" : "IN";
}

// 액션을 문자열로 변환
const char* ActionToString(unsigned char action) {
    return (action == PACKET_ACTION_PERMIT) ? "PERMIT" : "BLOCK";
}

// 콘솔 색상 설정
void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

// 콘솔 색상 초기화
void ResetConsoleColor() {
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// ============================================================================
// 드라이버 통신 함수
// ============================================================================

// 드라이버 연결
bool ConnectToDriver() {
    g_hDevice = CreateFileW(
        USER_MODE_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    return (g_hDevice != INVALID_HANDLE_VALUE);
}

// 드라이버 연결 해제
void DisconnectFromDriver() {
    if (g_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDevice);
        g_hDevice = INVALID_HANDLE_VALUE;
    }
}

// PID 차단 설정
bool SetBlockPid(unsigned long pid) {
    if (g_hDevice == INVALID_HANDLE_VALUE) return false;

    BLOCK_CONFIG config = { 0 };
    config.ProcessId = pid;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_SET_BLOCK_PID,
        &config,
        sizeof(config),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (success) {
        g_ulBlockedPid = pid;
    }
    return success ? true : false;
}

// PID 차단 해제
bool ResetBlockPid() {
    if (g_hDevice == INVALID_HANDLE_VALUE) return false;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_RESET_BLOCK_PID,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (success) {
        g_ulBlockedPid = 0;
    }
    return success ? true : false;
}

// 캡처 토글
bool ToggleCapture(bool enable) {
    if (g_hDevice == INVALID_HANDLE_VALUE) return false;

    CAPTURE_TOGGLE toggle = { 0 };
    toggle.Enable = enable ? 1 : 0;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_TOGGLE_CAPTURE,
        &toggle,
        sizeof(toggle),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (success) {
        g_bCapturing = enable;
    }
    return success ? true : false;
}

// 캡처 상태 조회
bool GetCaptureStatus(CAPTURE_STATUS* pStatus) {
    if (g_hDevice == INVALID_HANDLE_VALUE || pStatus == NULL) return false;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_GET_CAPTURE_STATUS,
        NULL,
        0,
        pStatus,
        sizeof(CAPTURE_STATUS),
        &bytesReturned,
        NULL
    );

    return success ? true : false;
}

// 패킷 배치 조회
bool GetPacketBatch(PACKET_BATCH* pBatch) {
    if (g_hDevice == INVALID_HANDLE_VALUE || pBatch == NULL) return false;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_GET_PACKET_BATCH,
        NULL,
        0,
        pBatch,
        sizeof(PACKET_BATCH),
        &bytesReturned,
        NULL
    );

    return success ? true : false;
}

// 패킷 큐 초기화
bool ClearPacketQueue() {
    if (g_hDevice == INVALID_HANDLE_VALUE) return false;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_CLEAR_PACKET_QUEUE,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    return success ? true : false;
}

// ============================================================================
// 패킷 처리 함수
// ============================================================================

// 패킷 정보를 콘솔에 출력
void PrintPacketInfo(const PACKET_INFO* pPacket) {
    // 액션에 따른 색상 설정
    if (pPacket->Action == PACKET_ACTION_BLOCK) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    }
    else {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    }

    std::cout << "[" << FileTimeToString(pPacket->Timestamp) << "] "
        << std::setw(6) << ActionToString(pPacket->Action) << " "
        << std::setw(3) << DirectionToString(pPacket->Direction) << " "
        << std::setw(5) << ProtocolToString(pPacket->Protocol) << " "
        << "PID:" << std::setw(6) << pPacket->ProcessId << " "
        << std::setw(15) << IpToString(pPacket->LocalAddress) << ":"
        << std::setw(5) << pPacket->LocalPort << " -> "
        << std::setw(15) << IpToString(pPacket->RemoteAddress) << ":"
        << std::setw(5) << pPacket->RemotePort << " "
        << "(" << pPacket->PacketSize << " bytes)"
        << std::endl;

    ResetConsoleColor();
}

// 패킷 정보를 로그 파일에 기록
void LogPacketInfo(const PACKET_INFO* pPacket) {
    std::lock_guard<std::mutex> lock(g_logMutex);

    if (g_logFile.is_open()) {
        g_logFile << FileTimeToString(pPacket->Timestamp) << ","
            << ActionToString(pPacket->Action) << ","
            << DirectionToString(pPacket->Direction) << ","
            << ProtocolToString(pPacket->Protocol) << ","
            << pPacket->ProcessId << ","
            << IpToString(pPacket->LocalAddress) << ","
            << pPacket->LocalPort << ","
            << IpToString(pPacket->RemoteAddress) << ","
            << pPacket->RemotePort << ","
            << pPacket->PacketSize
            << std::endl;
    }
}

// 패킷 배치 처리
void ProcessPacketBatch(const PACKET_BATCH* pBatch) {
    for (unsigned long i = 0; i < pBatch->PacketCount; i++) {
        const PACKET_INFO* pPacket = &pBatch->Packets[i];

        // 콘솔 출력
        PrintPacketInfo(pPacket);

        // 로그 파일 기록
        LogPacketInfo(pPacket);

        // 통계 업데이트
        g_ullTotalCaptured++;
        if (pPacket->Action == PACKET_ACTION_BLOCK) {
            g_ullTotalBlocked++;
        }
    }
}

// ============================================================================
// 워커 스레드
// ============================================================================

// 패킷 캡처 워커 스레드
unsigned int __stdcall CaptureThreadProc(void* pParam) {
    UNREFERENCED_PARAMETER(pParam);

    PACKET_BATCH* pBatch = (PACKET_BATCH*)malloc(sizeof(PACKET_BATCH));
    if (pBatch == NULL) {
        std::cerr << "[-] 메모리 할당 실패" << std::endl;
        return 1;
    }

    while (g_bRunning) {
        // 종료 이벤트 대기 (폴링 간격)
        DWORD waitResult = WaitForSingleObject(g_hStopEvent, CAPTURE_POLL_INTERVAL_MS);

        if (waitResult == WAIT_OBJECT_0) {
            // 종료 신호 수신
            break;
        }

        // 캡처 상태 확인
        if (!g_bCapturing) {
            continue;
        }

        // 패킷 배치 조회
        memset(pBatch, 0, sizeof(PACKET_BATCH));
        if (GetPacketBatch(pBatch)) {
            if (pBatch->PacketCount > 0) {
                ProcessPacketBatch(pBatch);

                // 남은 패킷이 있으면 계속 조회
                while (pBatch->RemainingPackets > 0 && g_bRunning && g_bCapturing) {
                    memset(pBatch, 0, sizeof(PACKET_BATCH));
                    if (!GetPacketBatch(pBatch) || pBatch->PacketCount == 0) {
                        break;
                    }
                    ProcessPacketBatch(pBatch);
                }
            }
        }
    }

    free(pBatch);
    return 0;
}

// 캡처 스레드 시작
bool StartCaptureThread() {
    if (g_hCaptureThread != NULL) {
        return true; // 이미 실행 중
    }

    // 종료 이벤트 생성
    g_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_hStopEvent == NULL) {
        std::cerr << "[-] 이벤트 생성 실패" << std::endl;
        return false;
    }

    // 스레드 생성
    g_hCaptureThread = (HANDLE)_beginthreadex( //CreateThread() => 적은 확률로 동기화 이슈를 발생시켜서, BSOD 유발의 원인이 되는 케이스가 있음
        NULL,
        0,
        CaptureThreadProc,
        NULL,
        0,
        NULL
    );

    if (g_hCaptureThread == NULL) {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
        std::cerr << "[-] 스레드 생성 실패" << std::endl;
        return false;
    }

    return true;
}

// 캡처 스레드 중지
void StopCaptureThread() {
    if (g_hCaptureThread == NULL) {
        return;
    }

    // 종료 신호 전송
    if (g_hStopEvent != NULL) {
        SetEvent(g_hStopEvent);
    }

    // 스레드 종료 대기 (최대 5초)
    WaitForSingleObject(g_hCaptureThread, 5000);

    // 핸들 정리
    CloseHandle(g_hCaptureThread);
    g_hCaptureThread = NULL;

    if (g_hStopEvent != NULL) {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
    }
}

// ============================================================================
// UI 함수
// ============================================================================

// 화면 클리어
void ClearScreen() {
    system("cls");
}

// 헤더 출력
void PrintHeader() {
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "============================================================" << std::endl;
    std::cout << "       WFP Packet Filtering & Capture System v2.0           " << std::endl;
    std::cout << "============================================================" << std::endl;
    ResetConsoleColor();
}

// 상태 표시
void PrintStatus() {
    std::cout << "\n--- 현재 상태 ---" << std::endl;

    // 캡처 상태
    std::cout << "패킷 캡처: ";
    if (g_bCapturing) {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[ON]";
    }
    else {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "[OFF]";
    }
    ResetConsoleColor();

    // 차단 PID
    std::cout << "  |  차단 PID: ";
    unsigned long blockedPid = g_ulBlockedPid;
    if (blockedPid > 0) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << blockedPid;
    }
    else {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "없음";
    }
    ResetConsoleColor();

    // 통계
    std::cout << "  |  캡처: " << g_ullTotalCaptured
        << "  차단: " << g_ullTotalBlocked << std::endl;
}

// 메뉴 출력
void PrintMenu() {
    std::cout << "\n--- 메뉴 ---" << std::endl;
    std::cout << "1. PID 차단 설정" << std::endl;
    std::cout << "2. PID 차단 해제" << std::endl;
    std::cout << "3. 패킷 캡처 토글" << std::endl;
    std::cout << "4. 패킷 큐 초기화" << std::endl;
    std::cout << "5. 드라이버 상태 조회" << std::endl;
    std::cout << "6. 화면 클리어" << std::endl;
    std::cout << "0. 종료" << std::endl;
    std::cout << "\n선택: ";
}

// PID 입력 처리
unsigned long InputPid() {
    unsigned long pid = 0;
    std::cout << "차단할 PID 입력: ";

    if (!(std::cin >> pid)) {
        std::cin.clear();
        std::cin.ignore(INT_MAX, '\n');
        std::cerr << "[-] 잘못된 입력입니다." << std::endl;
        return 0;
    }

    return pid;
}

// 드라이버 상태 출력
void PrintDriverStatus() {
    CAPTURE_STATUS status = { 0 };

    if (GetCaptureStatus(&status)) {
        std::cout << "\n--- 드라이버 상태 ---" << std::endl;
        std::cout << "캡처 상태: " << (status.IsCapturing ? "활성화" : "비활성화") << std::endl;
        std::cout << "차단 PID: " << status.BlockedPid << std::endl;
        std::cout << "큐 대기 패킷: " << status.QueuedPackets << std::endl;
        std::cout << "총 캡처 패킷: " << status.TotalCaptured << std::endl;
        std::cout << "총 차단 패킷: " << status.TotalBlocked << std::endl;
        std::cout << "드롭 패킷: " << status.DroppedPackets << std::endl;
    }
    else {
        std::cerr << "[-] 상태 조회 실패 (에러: " << GetLastError() << ")" << std::endl;
    }
}

// ============================================================================
// 메인 이벤트 루프
// ============================================================================

void EventLoop() {
    int choice = -1;

    while (g_bRunning) {
        PrintStatus();
        PrintMenu();

        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(INT_MAX, '\n');
            continue;
        }

        switch (choice) {
        case 0: // 종료
            g_bRunning = false;
            std::cout << "\n[*] 프로그램을 종료합니다..." << std::endl;
            break;

        case 1: // PID 차단 설정
        {
            unsigned long pid = InputPid();
            if (pid > 0) {
                if (SetBlockPid(pid)) {
                    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::cout << "[+] PID " << pid << " 차단 설정 완료" << std::endl;
                    ResetConsoleColor();
                }
                else {
                    std::cerr << "[-] 차단 설정 실패 (에러: " << GetLastError() << ")" << std::endl;
                }
            }
            break;
        }

        case 2: // PID 차단 해제
            if (ResetBlockPid()) {
                SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::cout << "[+] PID 차단 해제 완료" << std::endl;
                ResetConsoleColor();
            }
            else {
                std::cerr << "[-] 차단 해제 실패 (에러: " << GetLastError() << ")" << std::endl;
            }
            break;

        case 3: // 패킷 캡처 토글
        {
            bool newState = !g_bCapturing;
            if (ToggleCapture(newState)) {
                SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::cout << "[+] 패킷 캡처 " << (newState ? "활성화" : "비활성화") << " 완료" << std::endl;
                ResetConsoleColor();
            }
            else {
                std::cerr << "[-] 캡처 토글 실패 (에러: " << GetLastError() << ")" << std::endl;
            }
            break;
        }

        case 4: // 패킷 큐 초기화
            if (ClearPacketQueue()) {
                SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::cout << "[+] 패킷 큐 초기화 완료" << std::endl;
                ResetConsoleColor();
            }
            else {
                std::cerr << "[-] 큐 초기화 실패 (에러: " << GetLastError() << ")" << std::endl;
            }
            break;

        case 5: // 드라이버 상태 조회
            PrintDriverStatus();
            break;

        case 6: // 화면 클리어
            ClearScreen();
            PrintHeader();
            break;

        default:
            std::cout << "[!] 잘못된 선택입니다." << std::endl;
            break;
        }

        std::cout << std::endl;
    }
}

// ============================================================================
// 메인 함수
// ============================================================================

int main() {
    // 콘솔 한글 설정 (코드 페이지 949 - 한국어)
    SetConsoleCP(949);
    SetConsoleOutputCP(949);
    setlocale(LC_ALL, "Korean");
    SetConsoleTitleW(L"WFP Packet Filtering & Capture System");

    PrintHeader();

    // 1. 드라이버 연결
    std::cout << "[*] 드라이버 연결 중..." << std::endl;
    if (!ConnectToDriver()) {
        std::cerr << "[-] 드라이버 연결 실패 (에러: " << GetLastError() << ")" << std::endl;
        std::cout << "[!] 드라이버가 로드되어 있는지, 관리자 권한으로 실행 중인지 확인하세요." << std::endl;
        system("pause");
        return 1;
    }

    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "[+] 드라이버 연결 성공" << std::endl;
    ResetConsoleColor();

    // 2. 로그 파일 열기
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        g_logFile.open(LOG_FILE_NAME, std::ios::out | std::ios::app);
        if (g_logFile.is_open()) {
            // CSV 헤더 (파일이 새로 생성된 경우)
            g_logFile.seekp(0, std::ios::end);
            if (g_logFile.tellp() == 0) {
                g_logFile << "Timestamp,Action,Direction,Protocol,PID,LocalIP,LocalPort,RemoteIP,RemotePort,Size" << std::endl;
            }
            std::cout << "[+] 로그 파일 열기 성공: " << LOG_FILE_NAME << std::endl;
        }
        else {
            std::cerr << "[!] 로그 파일 열기 실패 (파일 로깅 비활성화)" << std::endl;
        }
    }

    // 3. 캡처 스레드 시작
    std::cout << "[*] 캡처 스레드 시작 중..." << std::endl;
    if (!StartCaptureThread()) {
        std::cerr << "[-] 캡처 스레드 시작 실패" << std::endl;
        DisconnectFromDriver();
        system("pause");
        return 1;
    }

    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "[+] 캡처 스레드 시작 성공" << std::endl;
    ResetConsoleColor();

    // 4. 이벤트 루프 실행
    std::cout << "\n[*] 시스템 준비 완료\n" << std::endl;
    EventLoop();

    // 5. 정리
    std::cout << "\n[*] 정리 중..." << std::endl;

    // 캡처 비활성화
    ToggleCapture(false);

    // 캡처 스레드 중지
    g_bRunning = false;
    StopCaptureThread();

    // 로그 파일 닫기
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        if (g_logFile.is_open()) {
            g_logFile.close();
        }
    }

    // 드라이버 연결 해제
    DisconnectFromDriver();

    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "[+] 정리 완료. 프로그램을 종료합니다." << std::endl;
    ResetConsoleColor();

    return 0;
}
