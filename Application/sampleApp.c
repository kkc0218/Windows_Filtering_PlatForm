// ============================================================================
// EX_FilterDrvApp_fixed.cpp - WFP Packet Filtering & Capture Application
// ============================================================================
// User Mode 응용프로그램 
// ============================================================================

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
#include <set>
#include <vector>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

// 공용 헤더 포함
#include "..\common\\Shared.h"

// ============================================================================
// 상수 정의
// ============================================================================
#define USER_MODE_DEVICE_NAME L"\\\\.\\WfpExampleLink"
#define LOG_FILE_NAME "packet_capture.log"
#define CAPTURE_POLL_INTERVAL_MS 100
#define UI_REFRESH_INTERVAL_MS 1000

// ============================================================================
// URL 정보 구조체
// ============================================================================
struct UrlInfo {
    std::string url;
    unsigned long blockCount;

    UrlInfo(const std::string& u, unsigned long c) : url(u), blockCount(c) {}

    bool operator<(const UrlInfo& other) const {
        return url < other.url;
    }
};

// ============================================================================
// 전역 변수
// ============================================================================
static HANDLE g_hDevice = INVALID_HANDLE_VALUE;
static HANDLE g_hCaptureThread = NULL;
static HANDLE g_hStopEvent = NULL;

static std::atomic<bool> g_bRunning(true);
static std::atomic<bool> g_bCapturing(false);
static std::atomic<unsigned long> g_ulBlockedPid(0);

// SNI 차단 관련
static std::atomic<bool> g_bSniBlockingEnabled(true);
static std::vector<UrlInfo> g_sniBlockedUrls;
static std::mutex g_sniMutex;

static std::mutex g_logMutex;
static std::ofstream g_logFile;

// 통계
static std::atomic<unsigned long long> g_ullTotalCaptured(0);
static std::atomic<unsigned long long> g_ullTotalBlocked(0);
static std::atomic<unsigned long long> g_ullSniBlocked(0);

// DNS 싱크홀 관련 (v3.0 신규)
static std::atomic<bool> g_bDnsSinkholeEnabled(false);
static std::atomic<unsigned long> g_ulSinkholeIp(0x7F000001);  // 127.0.0.1

// ============================================================================
// 유틸리티 함수
// ============================================================================

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

std::string IpToString(unsigned long ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << ((ip >> 0) & 0xFF);
    return oss.str();
}

const char* ProtocolToString(unsigned char protocol) {
    switch (protocol) {
    case PROTO_TCP:  return "TCP";
    case PROTO_UDP:  return "UDP";
    case PROTO_ICMP: return "ICMP";
    default:         return "OTHER";
    }
}

const char* DirectionToString(unsigned char direction) {
    return (direction == PACKET_DIR_OUTBOUND) ? "OUT" : "IN";
}

const char* ActionToString(unsigned char action) {
    return (action == PACKET_ACTION_PERMIT) ? "PERMIT" : "BLOCK";
}

void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void ResetConsoleColor() {
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// URL 정규화 (개선: 더 강력한 정규화)
std::string NormalizeUrl(const std::string& url) {
    std::string result = url;

    // 앞뒤 공백 제거
    while (!result.empty() && (result.front() == ' ' || result.front() == '\t')) {
        result.erase(0, 1);
    }
    while (!result.empty() && (result.back() == ' ' || result.back() == '\t' ||
        result.back() == '\r' || result.back() == '\n')) {
        result.pop_back();
    }

    // 소문자 변환
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);

    // https:// 또는 http:// 제거
    if (result.find("https://") == 0) {
        result = result.substr(8);
    }
    else if (result.find("http://") == 0) {
        result = result.substr(7);
    }

    // www. 접두사 제거
    if (result.find("www.") == 0) {
        result = result.substr(4);
    }

    // 경로 부분 제거 (첫 번째 / 이후)
    size_t slashPos = result.find('/');
    if (slashPos != std::string::npos) {
        result = result.substr(0, slashPos);
    }

    // 포트 번호 제거
    size_t colonPos = result.find(':');
    if (colonPos != std::string::npos) {
        result = result.substr(0, colonPos);
    }

    return result;
}

// ============================================================================
// 드라이버 통신 함수
// ============================================================================

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

void DisconnectFromDriver() {
    if (g_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDevice);
        g_hDevice = INVALID_HANDLE_VALUE;
    }
}

bool SetBlockPid(unsigned long pid) {
    if (g_hDevice == INVALID_HANDLE_VALUE) return false;

    BLOCK_CONFIG config;
    memset(&config, 0, sizeof(config));
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

bool ToggleCapture(bool enable) {
    if (g_hDevice == INVALID_HANDLE_VALUE) return false;

    CAPTURE_TOGGLE toggle;
    memset(&toggle, 0, sizeof(toggle));
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

bool GetCaptureStatus(CAPTURE_STATUS* pStatus) {
    if (g_hDevice == INVALID_HANDLE_VALUE || pStatus == NULL) return false;

    memset(pStatus, 0, sizeof(CAPTURE_STATUS));

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

bool GetPacketBatch(PACKET_BATCH* pBatch) {
    if (g_hDevice == INVALID_HANDLE_VALUE || pBatch == NULL) return false;

    memset(pBatch, 0, sizeof(PACKET_BATCH));

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
// SNI 차단 관련 함수 (수정됨)
// ============================================================================

// 전방 선언
bool GetSniBlockList();

bool ToggleSniUrl(const std::string& url, bool* isNowBlocked) {
    if (g_hDevice == INVALID_HANDLE_VALUE || url.empty()) return false;

    SNI_BLOCK_REQUEST request;
    SNI_BLOCK_RESPONSE response;

    // 구조체 초기화 (매우 중요!)
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));

    std::string normalizedUrl = NormalizeUrl(url);
    if (normalizedUrl.empty()) {
        std::cerr << "[-] 유효하지 않은 URL입니다." << std::endl;
        return false;
    }

    // 안전한 문자열 복사
    strncpy_s(request.Url, MAX_SNI_LENGTH, normalizedUrl.c_str(), _TRUNCATE);
    request.Action = SNI_ACTION_TOGGLE;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_SNI_BLOCK_URL,
        &request,
        sizeof(request),
        &response,
        sizeof(response),
        &bytesReturned,
        NULL
    );

    if (success && response.Success) {
        // 로컬 캐시 업데이트를 위해 전체 리스트 다시 조회
        GetSniBlockList();

        if (isNowBlocked) {
            *isNowBlocked = (response.IsBlocked != 0);
        }
        return true;
    }

    return false;
}

bool SetSniBlockingEnabled(bool enable) {
    if (g_hDevice == INVALID_HANDLE_VALUE) return false;

    SNI_TOGGLE toggle;
    memset(&toggle, 0, sizeof(toggle));
    toggle.Enable = enable ? 1 : 0;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_SNI_TOGGLE_BLOCKING,
        &toggle,
        sizeof(toggle),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (success) {
        g_bSniBlockingEnabled = enable;
    }
    return success ? true : false;
}

// SNI 차단 리스트 조회 (수정: 메모리 초기화 버그 수정)
bool GetSniBlockList() {
    if (g_hDevice == INVALID_HANDLE_VALUE) return false;

    std::vector<UrlInfo> tempList;

    SNI_LIST_REQUEST request;
    SNI_LIST_RESPONSE response;

    ULONG currentStartIndex = 0;
    bool hasMore = true;
    int retryCount = 0;
    const int maxRetries = 10;  // 무한 루프 방지

    while (hasMore && retryCount < maxRetries) {
        // 매우 중요: 각 요청마다 구조체 완전 초기화
        memset(&request, 0, sizeof(request));
        memset(&response, 0, sizeof(response));

        request.StartIndex = currentStartIndex;
        request.MaxCount = SNI_BLOCK_LIST_SIZE;

        DWORD bytesReturned = 0;
        BOOL success = DeviceIoControl(
            g_hDevice,
            IOCTL_WFP_SNI_GET_BLOCK_LIST,
            &request,
            sizeof(request),
            &response,
            sizeof(response),
            &bytesReturned,
            NULL
        );

        if (!success) {
            DWORD error = GetLastError();
            std::cerr << "[-] DeviceIoControl 실패 (에러: " << error << ")" << std::endl;
            return false;
        }

        // 디버그 출력
        std::cout << "[DEBUG] 응답: TotalCount=" << response.TotalCount
            << ", ReturnedCount=" << response.ReturnedCount
            << ", StartIndex=" << response.StartIndex << std::endl;

        // 응답 처리
        for (unsigned long i = 0; i < response.ReturnedCount; i++) {
            // NULL 종료 보장
            response.Entries[i].Url[MAX_SNI_LENGTH - 1] = '\0';

            // URL이 비어있지 않은지 확인
            if (response.Entries[i].Url[0] != '\0') {
                std::string urlStr(response.Entries[i].Url);

                // 유효한 URL인지 확인 (최소 길이)
                if (urlStr.length() >= 3) {
                    tempList.emplace_back(urlStr, response.Entries[i].BlockCount);
                    std::cout << "[DEBUG] URL 추가: " << urlStr
                        << " (차단 " << response.Entries[i].BlockCount << "회)" << std::endl;
                }
            }
        }

        // 다음 페이지 확인
        if (response.ReturnedCount == 0) {
            hasMore = false;
        }
        else {
            currentStartIndex += response.ReturnedCount;
            hasMore = (currentStartIndex < response.TotalCount);
        }

        retryCount++;
    }

    // 로컬 캐시 업데이트
    {
        std::lock_guard<std::mutex> lock(g_sniMutex);
        g_sniBlockedUrls = std::move(tempList);
    }

    return true;
}

bool ClearSniBlockList() {
    if (g_hDevice == INVALID_HANDLE_VALUE) return false;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_SNI_CLEAR_BLOCK_LIST,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (success) {
        std::lock_guard<std::mutex> lock(g_sniMutex);
        g_sniBlockedUrls.clear();
    }

    return success ? true : false;
}

// ============================================================================
// DNS 싱크홀 제어 함수 
// ============================================================================

bool SetDnsSinkholeEnabled(bool enable) {
    if (g_hDevice == INVALID_HANDLE_VALUE) return false;

    DNS_SINKHOLE_TOGGLE toggle;
    memset(&toggle, 0, sizeof(toggle));
    toggle.Enable = enable ? 1 : 0;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_DNS_SINKHOLE_TOGGLE,
        &toggle,
        sizeof(toggle),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (success) {
        g_bDnsSinkholeEnabled = enable;
    }
    return success ? true : false;
}

bool SetDnsSinkholeIp(unsigned long ip, unsigned short httpPort, unsigned short httpsPort) {
    if (g_hDevice == INVALID_HANDLE_VALUE) return false;

    DNS_SINKHOLE_CONFIG config;
    memset(&config, 0, sizeof(config));
    config.SinkholeIp = ip;
    config.HttpPort = httpPort;
    config.HttpsPort = httpsPort;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_DNS_SINKHOLE_SET_IP,
        &config,
        sizeof(config),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (success) {
        g_ulSinkholeIp = ip;
    }
    return success ? true : false;
}

bool GetDnsSinkholeStatus(DNS_SINKHOLE_STATUS* pStatus) {
    if (g_hDevice == INVALID_HANDLE_VALUE || pStatus == NULL) return false;

    memset(pStatus, 0, sizeof(DNS_SINKHOLE_STATUS));

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        g_hDevice,
        IOCTL_WFP_DNS_SINKHOLE_GET_STATUS,
        NULL,
        0,
        pStatus,
        sizeof(DNS_SINKHOLE_STATUS),
        &bytesReturned,
        NULL
    );

    if (success) {
        g_bDnsSinkholeEnabled = (pStatus->Enabled != 0);
        g_ulSinkholeIp = pStatus->SinkholeIp;
    }
    return success ? true : false;
}

// IP 주소를 문자열로 변환하는 헬퍼 함수 (호스트 바이트 오더)
std::string HostOrderIpToString(unsigned long ip) {
    char buffer[32];
    sprintf_s(buffer, sizeof(buffer), "%u.%u.%u.%u",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF);
    return std::string(buffer);
}

// 문자열을 IP 주소로 변환하는 헬퍼 함수 (호스트 바이트 오더)
bool StringToHostOrderIp(const std::string& str, unsigned long* outIp) {
    unsigned int a, b, c, d;
    if (sscanf_s(str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return false;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return false;
    }
    *outIp = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

// ============================================================================
// 패킷 처리 함수
// ============================================================================

void PrintPacketInfo(const PACKET_INFO& packet) {
    if (packet.Action == PACKET_ACTION_BLOCK) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    }
    else {
        SetConsoleColor(FOREGROUND_GREEN);
    }

    std::cout << "[" << FileTimeToString(packet.Timestamp) << "] "
        << std::setw(6) << ActionToString(packet.Action) << " "
        << std::setw(3) << DirectionToString(packet.Direction) << " "
        << std::setw(5) << ProtocolToString(packet.Protocol) << " "
        << "PID:" << std::setw(6) << packet.ProcessId << " "
        << IpToString(packet.LocalAddress) << ":" << packet.LocalPort
        << " -> "
        << IpToString(packet.RemoteAddress) << ":" << packet.RemotePort
        << " (" << packet.PacketSize << " bytes)"
        << std::endl;

    ResetConsoleColor();
}

void LogPacketInfo(const PACKET_INFO& packet) {
    std::lock_guard<std::mutex> lock(g_logMutex);

    if (g_logFile.is_open()) {
        g_logFile << FileTimeToString(packet.Timestamp) << ","
            << ActionToString(packet.Action) << ","
            << DirectionToString(packet.Direction) << ","
            << ProtocolToString(packet.Protocol) << ","
            << packet.ProcessId << ","
            << IpToString(packet.LocalAddress) << ","
            << packet.LocalPort << ","
            << IpToString(packet.RemoteAddress) << ","
            << packet.RemotePort << ","
            << packet.PacketSize
            << std::endl;
    }
}

void ProcessPacketBatch(const PACKET_BATCH* pBatch) {
    if (pBatch == NULL || pBatch->PacketCount == 0) {
        return;
    }

    for (unsigned long i = 0; i < pBatch->PacketCount; i++) {
        const PACKET_INFO& packet = pBatch->Packets[i];

        PrintPacketInfo(packet);
        LogPacketInfo(packet);

        g_ullTotalCaptured++;
        if (packet.Action == PACKET_ACTION_BLOCK) {
            g_ullTotalBlocked++;
        }
    }
}

// ============================================================================
// 캡처 스레드
// ============================================================================

unsigned int __stdcall CaptureThreadProc(void* param) {
    UNREFERENCED_PARAMETER(param);

    PACKET_BATCH* pBatch = (PACKET_BATCH*)malloc(sizeof(PACKET_BATCH));
    if (pBatch == NULL) {
        std::cerr << "[-] 배치 버퍼 할당 실패" << std::endl;
        return 1;
    }

    while (g_bRunning) {
        DWORD waitResult = WaitForSingleObject(g_hStopEvent, CAPTURE_POLL_INTERVAL_MS);

        if (waitResult == WAIT_OBJECT_0) {
            break;
        }

        if (g_bCapturing && g_hDevice != INVALID_HANDLE_VALUE) {
            while (true) {
                memset(pBatch, 0, sizeof(PACKET_BATCH));
                if (!GetPacketBatch(pBatch) || pBatch->PacketCount == 0) {
                    break;
                }
                ProcessPacketBatch(pBatch);
            }
        }
    }

    free(pBatch);
    return 0;
}

bool StartCaptureThread() {
    if (g_hCaptureThread != NULL) {
        return true;
    }

    g_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_hStopEvent == NULL) {
        std::cerr << "[-] 이벤트 생성 실패" << std::endl;
        return false;
    }

    g_hCaptureThread = (HANDLE)_beginthreadex(
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

void StopCaptureThread() {
    if (g_hCaptureThread == NULL) {
        return;
    }

    if (g_hStopEvent != NULL) {
        SetEvent(g_hStopEvent);
    }

    WaitForSingleObject(g_hCaptureThread, 5000);

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

void ClearScreen() {
    system("cls");
}

void PrintHeader() {
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "============================================================" << std::endl;
    std::cout << "       WFP Packet Filtering & Capture System v5.0           " << std::endl;
    std::cout << "   (TLS SNI + QUIC + DNS Blocking + DNS Sinkhole)           " << std::endl;
    std::cout << "============================================================" << std::endl;
    ResetConsoleColor();
}

void PrintStatus() {
    std::cout << "\n--- 현재 상태 ---" << std::endl;

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

    std::cout << "  |  SNI/QUIC 차단: ";
    if (g_bSniBlockingEnabled) {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[ON]";
    }
    else {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "[OFF]";
    }
    ResetConsoleColor();

    {
        std::lock_guard<std::mutex> lock(g_sniMutex);
        std::cout << " (" << g_sniBlockedUrls.size() << "개 URL)";
    }

    std::cout << "  |  DNS 싱크홀: ";
    if (g_bDnsSinkholeEnabled) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "[ON]";
    }
    else {
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "[OFF]";
    }
    ResetConsoleColor();

    std::cout << std::endl;
    std::cout << "캡처: " << g_ullTotalCaptured
        << "  PID차단: " << g_ullTotalBlocked
        << "  SNI/QUIC차단: " << g_ullSniBlocked << std::endl;
}

void PrintMenu() {
    std::cout << "\n--- 메뉴 ---" << std::endl;
    std::cout << "1. PID 차단 설정" << std::endl;
    std::cout << "2. PID 차단 해제" << std::endl;
    std::cout << "3. 패킷 캡처 토글" << std::endl;
    std::cout << "4. 패킷 큐 초기화" << std::endl;
    std::cout << "5. 드라이버 상태 조회" << std::endl;
    std::cout << "6. 화면 클리어" << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "--- SNI/QUIC/DNS URL 차단 ---" << std::endl;
    ResetConsoleColor();
    std::cout << "7. URL 차단/해제 (토글)" << std::endl;
    std::cout << "8. 차단 URL 목록 보기" << std::endl;
    std::cout << "9. SNI/QUIC 차단 기능 토글" << std::endl;
    std::cout << "10. 차단 URL 전체 초기화" << std::endl;
    std::cout << "11. 차단 URL 목록 새로고침" << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::cout << "--- DNS 싱크홀 (v3.0) ---" << std::endl;
    ResetConsoleColor();
    std::cout << "12. DNS 싱크홀 활성화/비활성화" << std::endl;
    std::cout << "13. 싱크홀 IP 설정" << std::endl;
    std::cout << "14. 싱크홀 상태 조회" << std::endl;
    std::cout << "0. 종료" << std::endl;
    std::cout << "\n선택: ";
}

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

std::string InputUrl() {
    std::string url;
    std::cout << "URL 입력 (예: naver.com, google.com): ";

    // 입력 버퍼 비우기
    std::cin.ignore(INT_MAX, '\n');
    std::getline(std::cin, url);

    if (url.empty()) {
        std::cerr << "[-] 잘못된 입력입니다." << std::endl;
        return "";
    }

    return NormalizeUrl(url);
}

void PrintDriverStatus() {
    CAPTURE_STATUS status;
    memset(&status, 0, sizeof(status));

    if (GetCaptureStatus(&status)) {
        std::cout << "\n--- 드라이버 상태 ---" << std::endl;
        std::cout << "캡처 상태: " << (status.IsCapturing ? "활성화" : "비활성화") << std::endl;
        std::cout << "차단 PID: " << status.BlockedPid << std::endl;
        std::cout << "큐 대기 패킷: " << status.QueuedPackets << std::endl;
        std::cout << "총 캡처 패킷: " << status.TotalCaptured << std::endl;
        std::cout << "총 PID 차단: " << status.TotalBlocked << std::endl;
        std::cout << "드롭 패킷: " << status.DroppedPackets << std::endl;
        std::cout << "--- SNI/QUIC/DNS 상태 ---" << std::endl;
        std::cout << "SNI/QUIC/DNS 차단: " << (status.SniBlockingEnabled ? "활성화" : "비활성화") << std::endl;
        std::cout << "차단 URL 수: " << status.SniBlockedUrls << std::endl;
        std::cout << "총 SNI/QUIC 차단: " << status.SniTotalBlocked << std::endl;

        g_ullSniBlocked = status.SniTotalBlocked;
        g_bSniBlockingEnabled = (status.SniBlockingEnabled != 0);

        // DNS 싱크홀 상태 추가 조회
        DNS_SINKHOLE_STATUS sinkholeStatus;
        if (GetDnsSinkholeStatus(&sinkholeStatus)) {
            std::cout << "--- DNS 싱크홀 상태 ---" << std::endl;
            SetConsoleColor(sinkholeStatus.Enabled ?
                (FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY) :
                FOREGROUND_GREEN);
            std::cout << "싱크홀: " << (sinkholeStatus.Enabled ? "활성화" : "비활성화");
            if (sinkholeStatus.Enabled) {
                std::cout << " (IP: " << HostOrderIpToString(sinkholeStatus.SinkholeIp) << ")";
            }
            std::cout << std::endl;
            ResetConsoleColor();
            std::cout << "수정된 DNS 응답: " << sinkholeStatus.TotalDnsModified << std::endl;
        }
    }
    else {
        std::cerr << "[-] 상태 조회 실패 (에러: " << GetLastError() << ")" << std::endl;
    }
}

// 차단 URL 목록 출력 (수정: 더 자세한 정보 및 버그 수정)
void PrintBlockedUrls() {
    std::cout << "[*] 드라이버에서 차단 목록 조회 중..." << std::endl;

    if (!GetSniBlockList()) {
        std::cerr << "[-] 차단 목록 조회 실패" << std::endl;
        return;
    }

    std::lock_guard<std::mutex> lock(g_sniMutex);

    std::cout << "\n========================================" << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::cout << "     차단 URL 목록 (" << g_sniBlockedUrls.size() << "개)" << std::endl;
    ResetConsoleColor();
    std::cout << "========================================" << std::endl;

    if (g_sniBlockedUrls.empty()) {
        std::cout << "(차단된 URL이 없습니다)" << std::endl;
    }
    else {
        std::cout << std::left << std::setw(5) << "번호"
            << std::setw(45) << "URL"
            << std::setw(12) << "차단 횟수" << std::endl;
        std::cout << "------------------------------------------------------------" << std::endl;

        int index = 1;
        for (const auto& info : g_sniBlockedUrls) {
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << std::left << std::setw(5) << index++;
            std::cout << std::setw(45) << info.url;
            std::cout << std::setw(12) << info.blockCount << std::endl;
            ResetConsoleColor();
        }
    }

    std::cout << "========================================" << std::endl;

    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "\n[차단 동작 방식 안내]" << std::endl;
    ResetConsoleColor();
    std::cout << "1. TLS SNI 기반 차단: HTTPS 연결의 Server Name을 검사하여 차단" << std::endl;
    std::cout << "2. QUIC (UDP 443) 차단: Initial 패킷의 SNI 파싱으로 차단" << std::endl;
    std::cout << "3. DNS 기반 IP 캐시: DNS 응답을 모니터링하여 차단 URL의 IP를 사전 캐시" << std::endl;
    std::cout << "4. IP 캐시 차단: 캐시된 IP로의 모든 443 포트 연결 차단" << std::endl;

    SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::cout << "\n[주의사항]" << std::endl;
    ResetConsoleColor();
    std::cout << "* 차단 효과를 보려면 브라우저를 완전히 종료 후 다시 시작하세요." << std::endl;
    std::cout << "* Chrome에서는 chrome://flags에서 QUIC 프로토콜을 비활성화하면 더 확실합니다." << std::endl;
    std::cout << "* 서브도메인도 함께 차단됩니다 (예: google.com 차단 시 mail.google.com도 차단)" << std::endl;
    std::cout << "* 같은 URL을 다시 입력하면 차단이 해제됩니다." << std::endl;
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
        case 0:
            g_bRunning = false;
            std::cout << "\n[*] 프로그램을 종료합니다..." << std::endl;
            break;

        case 1:
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

        case 2:
            if (ResetBlockPid()) {
                SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::cout << "[+] PID 차단 해제 완료" << std::endl;
                ResetConsoleColor();
            }
            else {
                std::cerr << "[-] 차단 해제 실패 (에러: " << GetLastError() << ")" << std::endl;
            }
            break;

        case 3:
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

        case 4:
            if (ClearPacketQueue()) {
                SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::cout << "[+] 패킷 큐 초기화 완료" << std::endl;
                ResetConsoleColor();
            }
            else {
                std::cerr << "[-] 큐 초기화 실패 (에러: " << GetLastError() << ")" << std::endl;
            }
            break;

        case 5:
            PrintDriverStatus();
            break;

        case 6:
            ClearScreen();
            PrintHeader();
            break;

        case 7:
        {
            std::string url = InputUrl();
            if (!url.empty()) {
                bool isNowBlocked = false;
                if (ToggleSniUrl(url, &isNowBlocked)) {
                    if (isNowBlocked) {
                        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                        std::cout << "[+] URL 차단 설정: " << url << std::endl;
                        std::cout << "    * HTTPS(TLS) + QUIC + DNS 기반 차단이 적용됩니다." << std::endl;
                        std::cout << "    * 브라우저를 완전히 종료 후 다시 시작해야 효과가 나타납니다." << std::endl;
                    }
                    else {
                        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                        std::cout << "[+] URL 차단 해제: " << url << std::endl;
                    }
                    ResetConsoleColor();
                }
                else {
                    std::cerr << "[-] URL 차단 설정 실패 (에러: " << GetLastError() << ")" << std::endl;
                }
            }
            break;
        }

        case 8:
            PrintBlockedUrls();
            break;

        case 9:
        {
            bool newState = !g_bSniBlockingEnabled;
            if (SetSniBlockingEnabled(newState)) {
                SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::cout << "[+] SNI/QUIC/DNS 차단 기능 " << (newState ? "활성화" : "비활성화") << " 완료" << std::endl;
                ResetConsoleColor();
            }
            else {
                std::cerr << "[-] SNI/QUIC 차단 토글 실패 (에러: " << GetLastError() << ")" << std::endl;
            }
            break;
        }

        case 10:
        {
            std::cout << "정말 모든 차단 URL을 초기화하시겠습니까? (y/n): ";
            char confirm;
            std::cin >> confirm;

            if (confirm == 'y' || confirm == 'Y') {
                if (ClearSniBlockList()) {
                    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::cout << "[+] 차단 URL 전체 초기화 완료" << std::endl;
                    ResetConsoleColor();
                }
                else {
                    std::cerr << "[-] 초기화 실패 (에러: " << GetLastError() << ")" << std::endl;
                }
            }
            else {
                std::cout << "[*] 취소되었습니다." << std::endl;
            }
            break;
        }

        case 11:
        {
            std::cout << "[*] 차단 URL 목록 새로고침 중..." << std::endl;
            if (GetSniBlockList()) {
                std::lock_guard<std::mutex> lock(g_sniMutex);
                SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::cout << "[+] 새로고침 완료 (" << g_sniBlockedUrls.size() << "개 URL)" << std::endl;
                ResetConsoleColor();
            }
            else {
                std::cerr << "[-] 새로고침 실패 (에러: " << GetLastError() << ")" << std::endl;
            }
            break;
        }

        // ================================================================
        // DNS 싱크홀 메뉴 
        // ================================================================
        case 12:
        {
            bool newState = !g_bDnsSinkholeEnabled;
            if (SetDnsSinkholeEnabled(newState)) {
                if (newState) {
                    SetConsoleColor(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                    std::cout << "[+] DNS 싱크홀 활성화됨" << std::endl;
                    std::cout << "    * 차단 URL에 대한 DNS 응답이 싱크홀 IP로 수정됩니다." << std::endl;
                    std::cout << "    * 현재 싱크홀 IP: " << HostOrderIpToString(g_ulSinkholeIp) << std::endl;
                }
                else {
                    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::cout << "[+] DNS 싱크홀 비활성화됨" << std::endl;
                }
                ResetConsoleColor();
            }
            else {
                std::cerr << "[-] DNS 싱크홀 토글 실패 (에러: " << GetLastError() << ")" << std::endl;
            }
            break;
        }

        case 13:
        {
            std::cout << "싱크홀 IP 입력 (예: 127.0.0.1): ";
            std::string ipStr;
            std::cin.ignore(INT_MAX, '\n');
            std::getline(std::cin, ipStr);

            unsigned long newIp = 0;
            if (!StringToHostOrderIp(ipStr, &newIp)) {
                std::cerr << "[-] 잘못된 IP 형식입니다." << std::endl;
                break;
            }

            std::cout << "HTTP 포트 입력 (기본: 80): ";
            unsigned short httpPort = 80;
            std::string portStr;
            std::getline(std::cin, portStr);
            if (!portStr.empty()) {
                httpPort = (unsigned short)std::stoi(portStr);
            }

            std::cout << "HTTPS 포트 입력 (기본: 443): ";
            unsigned short httpsPort = 443;
            std::getline(std::cin, portStr);
            if (!portStr.empty()) {
                httpsPort = (unsigned short)std::stoi(portStr);
            }

            if (SetDnsSinkholeIp(newIp, httpPort, httpsPort)) {
                SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::cout << "[+] 싱크홀 설정 완료" << std::endl;
                std::cout << "    IP: " << HostOrderIpToString(newIp) << std::endl;
                std::cout << "    HTTP 포트: " << httpPort << std::endl;
                std::cout << "    HTTPS 포트: " << httpsPort << std::endl;
                ResetConsoleColor();
            }
            else {
                std::cerr << "[-] 싱크홀 IP 설정 실패 (에러: " << GetLastError() << ")" << std::endl;
            }
            break;
        }

        case 14:
        {
            DNS_SINKHOLE_STATUS status;
            if (GetDnsSinkholeStatus(&status)) {
                std::cout << "\n--- DNS 싱크홀 상태 ---" << std::endl;
                SetConsoleColor(status.Enabled ?
                    (FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY) :
                    (FOREGROUND_GREEN));
                std::cout << "상태: " << (status.Enabled ? "활성화" : "비활성화") << std::endl;
                ResetConsoleColor();
                std::cout << "싱크홀 IP: " << HostOrderIpToString(status.SinkholeIp) << std::endl;
                std::cout << "HTTP 포트: " << status.HttpPort << std::endl;
                std::cout << "HTTPS 포트: " << status.HttpsPort << std::endl;
                std::cout << "--- 통계 ---" << std::endl;
                std::cout << "수정된 DNS 응답: " << status.TotalDnsModified << std::endl;
                std::cout << "싱크홀 리다이렉션: " << status.TotalRedirected << std::endl;
            }
            else {
                std::cerr << "[-] 싱크홀 상태 조회 실패 (에러: " << GetLastError() << ")" << std::endl;
            }
            break;
        }

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
    // 콘솔 한글 설정
    SetConsoleCP(949);
    SetConsoleOutputCP(949);
    setlocale(LC_ALL, "Korean");
    SetConsoleTitleW(L"WFP Packet Filtering & Capture System v5.0 (SNI/QUIC/DNS + Sinkhole)");

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

    // 4. SNI 차단 리스트 초기 로드
    std::cout << "[*] SNI 차단 리스트 로드 중..." << std::endl;
    if (GetSniBlockList()) {
        std::lock_guard<std::mutex> lock(g_sniMutex);
        std::cout << "[+] SNI 차단 리스트 로드 완료 (" << g_sniBlockedUrls.size() << "개 URL)" << std::endl;
    }

    // SNI/QUIC/DNS 차단 기본 활성화
    SetSniBlockingEnabled(true);

    // 5. 안내 메시지
    std::cout << "\n[*] 시스템 준비 완료" << std::endl;
    std::cout << "\n========================================================" << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "        URL 차단 안내 (Ultimate: SNI + QUIC + DNS)       " << std::endl;
    ResetConsoleColor();
    std::cout << "========================================================" << std::endl;
    std::cout << "* 이 시스템은 WFP(Windows Filtering Platform) 기반으로" << std::endl;
    std::cout << "  커널 수준에서 네트워크 트래픽을 필터링합니다." << std::endl;
    std::cout << std::endl;
    std::cout << "* 차단 방식:" << std::endl;
    std::cout << "  1. TLS SNI 검사 - HTTPS 연결의 Server Name 확인" << std::endl;
    std::cout << "  2. QUIC Initial 검사 - UDP 443 패킷의 SNI 파싱" << std::endl;
    std::cout << "  3. DNS 응답 모니터링 - 차단 URL의 IP 사전 캐시" << std::endl;
    std::cout << "  4. IP 캐시 기반 차단 - 443 포트 연결 사전 차단" << std::endl;
    std::cout << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::cout << "* 중요: 차단 효과를 보려면 브라우저를 완전히 종료하세요!" << std::endl;
    ResetConsoleColor();
    std::cout << "========================================================\n" << std::endl;

    // 6. 이벤트 루프 실행
    EventLoop();

    // 7. 정리
    std::cout << "\n[*] 정리 중..." << std::endl;

    ToggleCapture(false);
    g_bRunning = false;
    StopCaptureThread();

    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        if (g_logFile.is_open()) {
            g_logFile.close();
        }
    }

    DisconnectFromDriver();

    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "[+] 정리 완료. 프로그램을 종료합니다." << std::endl;
    ResetConsoleColor();

    return 0;
}
