#pragma once

#include "krabs.hpp"
#include "nlohmann/json.hpp"

#include <mutex>
#include <vector>
#include <thread>
#include <condition_variable>


#define EtwAgentName L"EtwMon"
#define DPRINT_ERROR(level, fmt, ...) EtwMon::log(EtwMon::LogError, "[%s] " fmt, __FUNCTION__, ##__VA_ARGS__)


const GUID EMPTY_GUID = { 0x0, 0x0, 0x0, { 0x0, 0x0, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0 } };


#define DBG_LOG(format, ...) \
    do { \
        printf("[%d] %s (Thread ID: %lu, Process ID: %lu): ", \
               __LINE__, \
               __FUNCTION__, \
               GetCurrentThreadId(), \
               GetCurrentProcessId()); \
        printf(format, ##__VA_ARGS__); \
        printf("\n"); \
    } while (0)



namespace EtwEvents
{
    namespace Process
    {
        static constexpr int EVENT_PROCESS_START_MASK = 0x10;
        static constexpr int EVENT_THREAD_START_MASK = 0x20;

        static constexpr int EVENT_PROCESS_START = 1;
        static constexpr int EVENT_PROCESS_STOP = 2;
        static constexpr int EVENT_THREAD_START = 3;
        static constexpr int EVENT_THREAD_STOP = 4;
        static constexpr int EVENT_IMAGE_LOAD = 5;
        static constexpr int EVENT_IMAGE_UNLOAD = 6;
        static constexpr int EVENT_CPU_BASE_PRIORITY_CHANGE = 7;
        static constexpr int EVENT_CPU_PRIORITY_CHANGE = 8;
        static constexpr int EVENT_PAGE_PRIORITY_CHANGE = 9;
        static constexpr int EVENT_IO_PRIORITY_CHANGE = 10;
    }
}



class EtwMon {
public:
    typedef std::function<void(const EVENT_RECORD&, const krabs::trace_context&)> EtwEventCallback;
    using CustomProcessAlertFunction = std::function<void(const nlohmann::json&)>;

    enum LogLevel {
        LogDisabled = 0,
        LogError,
        LogDefault,
        LogVerbose,
        LogNoisy,
        LogLevelMax
    };

    typedef struct _PROVIDER_INFO {
        std::wstring providerName;
        EtwEventCallback callback;
        std::vector<unsigned short> eventIds;
        std::vector<unsigned short> accesMasks;
        int traceLevel;
    } PROVIDER_INFO, * PPROVIDER_INFO;



    EtwMon(const std::wstring& traceName, LogLevel maxLog, CustomProcessAlertFunction customProcessFunc = nullptr);
    ~EtwMon();


    void log(LogLevel level, const char* fmt, ...);
    bool RegisterProviders(const std::vector<PROVIDER_INFO>& providerInfoVector);
	void PrintEventInfo(krabs::parser& parser, const EVENT_RECORD& record, const krabs::trace_context& trace_context, nlohmann::json& jsonOutput);
	void PrintPropertyInfo(krabs::parser& parser, nlohmann::json& jsonOutput, const EVENT_RECORD& record, const krabs::trace_context& trace_context);
    void PrintEventInfo(const EVENT_RECORD& record, const krabs::trace_context& trace_context, nlohmann::json& jsonOutput);
    void cb_OnGenericEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context);

    void start();
    void stop();



private:
    krabs::user_trace etwTrace;
    bool debugMode = true;
    bool bTraceStarted = false;

    std::thread alertProcessingThread;

    std::thread traceThread;

    LogLevel maxLogLevel;

    std::vector<std::unique_ptr<krabs::provider<>>> providers;
    std::vector<std::unique_ptr<krabs::event_filter>> filters;

};

int initEtwMon();
