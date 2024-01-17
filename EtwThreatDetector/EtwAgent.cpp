#include "EtwAgent.h"
#include "EtwUtils.h"
#include "nlohmann\json.hpp"

#include <windows.h>
#include <iostream>
#include <Psapi.h>
#include <TlHelp32.h>
#include <regex>
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>
#include <string>
#include <cstdlib>
#include <ctime>

CRITICAL_SECTION fileCriticalSection;
CRITICAL_SECTION logCriticalSection;

std::string g_curDirectory;
std::string g_logFileName = "EventLogs.txt";
DWORD g_curProcId = 0;

std::map<std::pair<int, std::string>, int> processMap;
std::map<int, int> pidMap;
std::mutex mapMutex;
std::deque<nlohmann::json> g_jsonList;
std::unordered_map<std::string, bool > g_monitoredProcesses;
std::string randomString;
#define BATCH_SIZE 100


template<typename T>
T safe_parse(krabs::parser& parser, const std::wstring& property_name, const T& default_value) {
    try {
        return parser.parse<T>(property_name);
    }
    catch (const std::exception&) {
        return default_value;
    }
}

void AssignJsonValue(nlohmann::json& propertyJson, const std::string& key, const std::string& value) {
    try {
        propertyJson[key] = value;
    }
    catch (const nlohmann::json::type_error & e) {
        std::cerr << "Exception caught: " << e.what() << '\n';
        propertyJson[key] = "";
    }
}

std::string GetProcessNameFromEvent(DWORD processId) {
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

    if (processHandle) {
        TCHAR processPath[MAX_PATH];
        if (GetModuleFileNameEx(processHandle, NULL, processPath, MAX_PATH)) {
            // Process path is obtained, extract the process name
            CloseHandle(processHandle);

            std::string fullPath(processPath);
            size_t lastBackslash = fullPath.find_last_of("\\");
            if (lastBackslash != std::string::npos) {
                return fullPath.substr(lastBackslash + 1);
            }
        }
        else
        {
            CloseHandle(processHandle);
            return EtwUtils::GetProcessNameById(processId);
        }
    }
    return "";
}

std::string generateRandomString(int length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const int charsetSize = sizeof(charset) - 1;

    std::string randomString;
    srand(static_cast<unsigned int>(time(nullptr)));

    for (int i = 0; i < length; ++i) {
        randomString += charset[rand() % charsetSize];
    }
    return randomString;
}

EtwMon::EtwMon(const std::wstring& traceName, LogLevel maxLog, CustomProcessAlertFunction customProcessFunc)
    : etwTrace(traceName), maxLogLevel(maxLog) {
}

EtwMon::~EtwMon() {

    if (bTraceStarted)
    {
        bTraceStarted = false;
        etwTrace.stop();
    }

}

void EtwMon::start() {

    if (bTraceStarted) return;

    try {
        bTraceStarted = true;
        etwTrace.start();
    }
    catch (const std::exception& e) {
        DPRINT_ERROR(ErrorDefault, "Standard exception caught! Message: %s", e.what());
    }
    catch (...) {
        DPRINT_ERROR(ErrorDefault, "Unknown exception caught!");
    }
}

void EtwMon::stop() {
    if (bTraceStarted)
    {
        etwTrace.stop();
    }
}

void DeleteCriticalSectionForFile() {
    DeleteCriticalSection(&fileCriticalSection);
}

void InitializeCriticalSectionForFile() {
    InitializeCriticalSection(&fileCriticalSection);
}

void DeleteCriticalSectionForLog() {
    DeleteCriticalSection(&logCriticalSection);
}

void InitializeCriticalSectionForLog() {
    InitializeCriticalSection(&logCriticalSection);
}

void EtwMon::PrintEventInfo(const EVENT_RECORD& record, const krabs::trace_context& trace_context, nlohmann::json& jsonOutput) {
    krabs::schema schema(record, trace_context.schema_locator);

    DWORD flags = record.EventHeader.Flags;
    auto originProcessPath = EtwUtils::GetProcessPathFromId(record.EventHeader.ProcessId);
    DWORD eventProperty = record.EventHeader.EventProperty;

    auto activityGuid = schema.activity_id();
    char activityGuidString[100] = {0};
    snprintf(activityGuidString, sizeof(activityGuidString), "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        activityGuid.Data1, activityGuid.Data2, activityGuid.Data3,
        activityGuid.Data4[0], activityGuid.Data4[1], activityGuid.Data4[2], activityGuid.Data4[3],
        activityGuid.Data4[4], activityGuid.Data4[5], activityGuid.Data4[6], activityGuid.Data4[7]);


    std::wstring taskNameWs = schema.task_name();
    std::string taskName(taskNameWs.begin(), taskNameWs.end());

    std::wstring opcodeNameWs = schema.opcode_name();
    std::string opcodeName(opcodeNameWs.begin(), opcodeNameWs.end());

    std::wstring providerNameWs = schema.provider_name();
    std::string providerName(providerNameWs.begin(), providerNameWs.end());

    jsonOutput["EventId"] = record.EventHeader.EventDescriptor.Id;
    //jsonOutput["Version"] = record.EventHeader.EventDescriptor.Version;
    //jsonOutput["Level"] = record.EventHeader.EventDescriptor.Level;
    jsonOutput["Opcode"] = record.EventHeader.EventDescriptor.Opcode;
    //jsonOutput["Channel"] = record.EventHeader.EventDescriptor.Channel;
    jsonOutput["Task"] = record.EventHeader.EventDescriptor.Task;
    //jsonOutput["Keyword"] = record.EventHeader.EventDescriptor.Keyword;

    jsonOutput["TaskName"] = taskName;
    jsonOutput["OpcodeName"] = opcodeName;
    //jsonOutput["ActivityId"] = activityGuidString;
    jsonOutput["ProviderName"] = providerName;
    //jsonOutput["DecodingSource"] = schema.decoding_source();
    jsonOutput["ProcessID"] = record.EventHeader.ProcessId;
    jsonOutput["ThreadID"] = record.EventHeader.ThreadId;
    jsonOutput["TimeStamp"] = record.EventHeader.TimeStamp.QuadPart;
    //jsonOutput["Property"] = record.EventHeader.EventProperty;
    //jsonOutput["Flags"] = record.EventHeader.Flags;
    //jsonOutput["KernelTime"] = record.EventHeader.KernelTime;
    //jsonOutput["UserTime"] = record.EventHeader.UserTime;
    jsonOutput["Size"] = record.EventHeader.Size;
    jsonOutput["ProcessPath"] = originProcessPath;


    if (flags & EVENT_HEADER_FLAG_EXTENDED_INFO) {
        log(LogVerbose, "Event contains extended information.\n");
    }
    if (flags & EVENT_HEADER_FLAG_PRIVATE_SESSION) {
        log(LogVerbose, "Event belongs to a private session.\n");
    }
    if (flags & EVENT_HEADER_FLAG_STRING_ONLY) {
        log(LogVerbose, "Event contains only string data.\n");
    }


    if (eventProperty & EVENT_ENABLE_PROPERTY_SID) {
        log(LogVerbose, "Security identifier is enabled.\n");
    }
    if (eventProperty & EVENT_ENABLE_PROPERTY_TS_ID) {
        log(LogVerbose, "Thread session ID is enabled.\n");
    }
}

void EtwMon::PrintPropertyInfo(krabs::parser& parser, nlohmann::json& jsonOutput, const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    nlohmann::json propertyJson;
    bool bPrintJson = false;
    
    for (krabs::property property : parser.properties()) {

        try {
            auto processID = safe_parse<uint32_t>(parser, L"ProcessID", 0);

            if (processID != 0)
            {
                propertyJson["ProcessPath"] = EtwUtils::GetProcessPathFromId(processID);

                if (processID > 4 &&
                    processID != record.EventHeader.ProcessId &&
                    (record.EventHeader.EventDescriptor.Id == EtwEvents::Process::EVENT_PROCESS_START || record.EventHeader.EventDescriptor.Id == EtwEvents::Process::EVENT_THREAD_START) &&
                    jsonOutput["ProviderName"] == "Microsoft-Windows-Kernel-Process" )
                {
                    auto processPath = GetProcessNameFromEvent(processID);
                    if (!g_monitoredProcesses.empty())
                    {
                        g_monitoredProcesses[processPath] = 1;
                        bPrintJson = true;
                    }
                }
            }

            auto parentprocessID = safe_parse<uint32_t>(parser, L"ParentProcessID", 0);

            if (parentprocessID != 0)
            {
                propertyJson["ParentProcessPath"] = EtwUtils::GetProcessPathFromId(parentprocessID);
            }

            std::wstring wsPropertyName = property.name();
            std::string propertyName(wsPropertyName.begin(), wsPropertyName.end());

            log(LogVerbose, "[Property][%d][%ws] Parsing...\n", property.type(), wsPropertyName.c_str());

            switch (property.type())
            {
                case TDH_INTYPE_UINT32:
                case TDH_INTYPE_HEXINT32:
                {
                    uint32_t value = safe_parse<uint32_t>(parser, wsPropertyName, 0);
                    propertyJson[propertyName] = value;

                    log(LogVerbose, "[Property][%d][%ws] %d\n", property.type(), wsPropertyName.c_str(), value);
                    break;
                }
                case TDH_INTYPE_UNICODESTRING:
                {
                    std::wstring wsValue = safe_parse<std::wstring>(parser, wsPropertyName, L"");
                    std::string value(wsValue.begin(), wsValue.end());

                    if (value.length() < 2) break;

                    if (EtwUtils::ContainsNonAscii(value))
                    {
                        propertyJson[propertyName] = "";
                        log(LogVerbose, "[Property][%d][%ws] non printable: %s - size %d\n", property.type(), wsPropertyName.c_str(), value.c_str(), value.length());
                        break;
                    }

                    EtwUtils::RemoveNewLines(value);
                    propertyJson[propertyName] = value;

                    log(LogVerbose, "[Property][%d][%ws] %ws\n", property.type(), wsPropertyName.c_str(), value.c_str());
                    break;
                }
                case TDH_INTYPE_ANSISTRING:
                {
                    std::string value = safe_parse<std::string>(parser, wsPropertyName, "");

                    if (value.length() < 2) break;

                    if (EtwUtils::ContainsNonAscii(value))
                    {
                        propertyJson[propertyName] = "";
                        log(LogVerbose, "[Property][%d][%ws] non printable: %s - size %d\n", property.type(), wsPropertyName.c_str(), value.c_str(), value.length());
                        break;
                    }

                    EtwUtils::RemoveNewLines(value);
                    propertyJson[propertyName] = value;

                    log(LogVerbose, "[Property][%d][%ws] %s - size %d\n", property.type(), wsPropertyName.c_str(), value.c_str(), value.length());
                    break;
                }
                //case TDH_INTYPE_INT8:
                //{
                //    auto value = parser.parse<byte>(wsPropertyName);

                //    propertyJson[propertyName] = value;

                //    log(LogVerbose, "[Property][%d][%ws] %d\n", property.type(), wsPropertyName.c_str(), value);
                //    break;
                //}
                case TDH_INTYPE_BOOLEAN:
                {
                    BOOL value = safe_parse<BOOL>(parser, wsPropertyName, false);

                    propertyJson[propertyName] = value;

                    log(LogVerbose, "[Property][%d][%ws] %d\n", property.type(), wsPropertyName.c_str(), value);
                    break;
                }

                case TDH_INTYPE_UINT16:
                {
                    uint16_t value = safe_parse<uint16_t>(parser, wsPropertyName, 0);

                    propertyJson[propertyName] = value;

                    log(LogVerbose, "[Property][%d][%ws] %d\n", property.type(), wsPropertyName.c_str(), value);
                    break;
                }


                case TDH_INTYPE_UINT64:
                {
                    uint64_t value = safe_parse<uint64_t>(parser, wsPropertyName, 0);

                    propertyJson[propertyName] = value;

                    log(LogVerbose, "[Property][%d][%ws] %d\n", property.type(), wsPropertyName.c_str(), value);
                    break;
                }

                case TDH_INTYPE_GUID:
                {
                    GUID value = safe_parse<krabs::guid>(parser, wsPropertyName, EMPTY_GUID);

                    char guidString[100] = { 0 };
                    snprintf(guidString, sizeof(guidString), "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                        value.Data1, value.Data2, value.Data3,
                        value.Data4[0], value.Data4[1], value.Data4[2], value.Data4[3],
                        value.Data4[4], value.Data4[5], value.Data4[6], value.Data4[7]);

                    propertyJson[propertyName] = guidString;

                    log(LogVerbose, "[Property][%d][%ws] ", property.type(), wsPropertyName.c_str());

                    break;
                }
                default:
                {
                    log(LogVerbose, "[Property][%d][%ws] Unhandled type \n", property.type(), wsPropertyName.c_str());
                    break;
                }
            }

        }

        catch (const std::exception & e) {
            krabs::schema schema(record, trace_context.schema_locator);
            std::wstring providerNameWs = schema.provider_name();
            DPRINT_ERROR(ErrorDefault, "Standard exception caught! Message: %s - Event Id: %d - Provider Name: %ws", e.what(), record.EventHeader.EventDescriptor.Id, providerNameWs.c_str());
            continue;
        }


    }

    jsonOutput["EventData"] = propertyJson;

    //if (bPrintJson)
    //    std::cout << jsonOutput << std::endl;
}

void EtwMon::log(LogLevel level, const char* fmt, ...) {
    if (level <= maxLogLevel && level != LogDisabled && level != LogError) {
        va_list args;
        va_start(args, fmt);
        printf("[EtwMon][LOG][%d] ", level);
        vprintf(fmt, args);
        va_end(args);
    }
    else if (level == LogError && level != LogDisabled)
    {
        va_list args;
        va_start(args, fmt);

        printf("[EtwMon][ERROR][%d] ", level);
        vprintf(fmt, args);

        DWORD error = GetLastError();
        LPVOID errorMsg;
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            error,
            0,
            (LPSTR)&errorMsg,
            0,
            NULL
        );
        printf("\nLast error code: %lu, Message: %ws\n", error, (wchar_t*)errorMsg);
        LocalFree(errorMsg);

        va_end(args);
    }
}

void addProcess(int pid, const std::string& processPath) {
    auto key = std::make_pair(pid, processPath);
    if (processMap.find(key) == processMap.end()) {
        processMap[key] = 1;
    }
    else {
        processMap[key]++;
    }
}

void addPid(int pid) {
    if (pidMap.find(pid) == pidMap.end()) {
        pidMap[pid] = 1;
    }
    else {
        pidMap[pid]++;
    }
}

void printMapPeriodically() {
    while (true) {
        std::vector<std::pair<std::pair<int, std::string>, int>> sortedProcesses;
        printf("\n\n");
        {
            for (const auto& pair : processMap) {
                sortedProcesses.push_back(pair);
            }
        }
         
        std::sort(sortedProcesses.begin(), sortedProcesses.end(),
            [](const auto& a, const auto& b) {
                return a.second > b.second;
            }
        );


        for (const auto& pair : sortedProcesses) {
            DBG_LOG("PID: %d, Process: %s, Count: %d", pair.first.first, pair.first.second.c_str(), pair.second);
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void printPidCountMapPeriodically() {
    while (true) {
        {
            printf("\n\n");
            for (const auto& pair : pidMap) {
                DBG_LOG("PID: %d, ProcessPath : %s, Count: %d", pair.first, EtwUtils::GetProcessPathFromId(pair.first).c_str() ,pair.second);
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void WriteJsonToFile(const nlohmann::json& jsonData, const std::string& filePath) {
    std::string serializedJson = jsonData.dump();

    EnterCriticalSection(&fileCriticalSection);

    std::ofstream file(filePath, std::ios::app);
    if (file.is_open()) {
        file << serializedJson << std::endl;
    }

    LeaveCriticalSection(&fileCriticalSection);
}

void WriteJsonBatchToFile(const std::vector<nlohmann::json>& batch) {

    std::string g_logFile = "C:\\APPAIEtwLogger\\" + randomString +"_"+ g_logFileName ;

    EnterCriticalSection(&fileCriticalSection);

    std::ofstream file(g_logFile, std::ios::app);
    if (file.is_open()) {
        for (const auto& jsonItem : batch) {
            file << jsonItem.dump() << std::endl;
        }
    }


    LeaveCriticalSection(&fileCriticalSection);
}

void WriteBatchAsync(const std::vector<nlohmann::json>& batch) {
    auto batchCopy = batch;

    std::thread writeThread(WriteJsonBatchToFile, batchCopy);
    writeThread.detach();
}

void ProcessJsonList() {
    std::deque<nlohmann::json> localJsonList;
    std::vector<nlohmann::json> batchToWrite;
    batchToWrite.reserve(BATCH_SIZE); 

    while (true) {
        {
            EnterCriticalSection(&logCriticalSection);
            localJsonList.swap(g_jsonList);
            LeaveCriticalSection(&logCriticalSection);
        }

        while (!localJsonList.empty()) {
            batchToWrite.push_back(std::move(localJsonList.front()));
            localJsonList.pop_front();

            if (batchToWrite.size() >= BATCH_SIZE) {
                WriteBatchAsync(batchToWrite);  
                batchToWrite.clear();
            }
        }

        if (!batchToWrite.empty()) {
            WriteBatchAsync(batchToWrite);  
            batchToWrite.clear();
        }

        Sleep(10);
    }
}

void EtwMon::cb_OnGenericEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);
    nlohmann::json jsonOutput;
    std::string eventProcessName;

    if (record.EventHeader.ProcessId == g_curProcId)
        return;

    if (!g_monitoredProcesses.empty()) {
        eventProcessName = GetProcessNameFromEvent(record.EventHeader.ProcessId);

        if(eventProcessName.empty() || g_monitoredProcesses.find(eventProcessName) == g_monitoredProcesses.end())
            return;
    }

    //addPid(record.EventHeader.ProcessId);
    addProcess(record.EventHeader.ProcessId, EtwUtils::GetProcessPathFromId(record.EventHeader.ProcessId));

    try {
        PrintEventInfo(record, trace_context, jsonOutput);
        PrintPropertyInfo(parser, jsonOutput, record, trace_context);


        EnterCriticalSection(&logCriticalSection);
        g_jsonList.emplace_back(std::move(jsonOutput));
        LeaveCriticalSection(&logCriticalSection);


        //std::string filePath = g_curDirectory + "\\EventLogs.txt";
        //WriteJsonToFile(jsonOutput, filePath);
    }

    catch (const std::exception& e) {
        std::wstring providerNameWs = schema.provider_name();
        DPRINT_ERROR(ErrorDefault, "Standard exception caught! Message: %s - Event Id: %d - Provider Name: %ws", e.what(), record.EventHeader.EventDescriptor.Id, providerNameWs.c_str());
    }
    catch (...) {
        DPRINT_ERROR(ErrorDefault, "Unknown exception caught!");
    }
}

bool EtwMon::RegisterProviders(const std::vector<PROVIDER_INFO>& providerInfoVector) {
    bool bResult = false;

    for (const auto& providerInfo : providerInfoVector) {

        try
        {
            std::unique_ptr<krabs::provider<>> provider(new krabs::provider<>(providerInfo.providerName));

            if (!providerInfo.eventIds.empty()) {

                //for (auto& accessMask : providerInfo.accesMasks) {
                //    provider->any(accessMask);
                //}

                std::unique_ptr<krabs::event_filter> filter(new krabs::event_filter(providerInfo.eventIds));
                filter->add_on_event_callback(providerInfo.callback);
                provider->add_filter(*filter);
                filters.push_back(std::move(filter));
            }
            else {
                provider->add_on_event_callback(providerInfo.callback);
            }

            //provider->level(providerInfo.traceLevel);
            etwTrace.enable(*provider);
            providers.push_back(std::move(provider));

            log(LogDefault, "Successfully registered %ws \n", providerInfo.providerName.c_str());
            bResult = true;
        }
        catch (const std::exception & e) {
            DPRINT_ERROR(ErrorDefault, "Standard exception caught! Message: %s", e.what());
            continue;
        }
        catch (...) {
            DPRINT_ERROR(ErrorDefault, "Unknown exception caught!");
            continue;
        }
    }

    return bResult;
}

void EtwAlertProcessor(const nlohmann::json& jsonAlert) {
    //std::cout << "\n\n[*] New ETW LOG:\n";
    //std::cout << jsonAlert.dump(4) << std::endl;
}

void LoadProcessNames() {

    std::ifstream file("C:\\APPAIEtwLogger\\processes.txt");
    if (!file.is_open()) {
        std::cout << "processes.txt not found. Monitoring all processes." << std::endl;
        return;
    }

    std::string processName;
   /*
   int i = 0;
    while (std::getline(file, processName)) {
        
        std::cout << "Monitored ProcessName: " << processName << std::endl;
        if (i == 0) g_logFileName = processName + ".txt";
        g_monitoredProcesses[processName] = true;
        i++;
    }
    */
    int totalProcesses = 0;
    while (std::getline(file, processName)) {
        totalProcesses++;
    }
    if (totalProcesses == 0) {
        std::cout << "No processes found. Exiting." << std::endl;
        return;
    }
    srand(static_cast<unsigned int>(time(nullptr)));
    int randomIndex = rand() % totalProcesses;
    file.clear();
    file.seekg(0, std::ios::beg);
    int currentIndex = 0;
    while(std::getline(file, processName)) {
            if (currentIndex == randomIndex) {
            std::cout << std::endl << "Randomly Selected Process: " << processName << std::endl;
            g_logFileName = processName + ".txt";
            g_monitoredProcesses[processName] = true;
            //break;
        }
        else {
                g_monitoredProcesses[processName] = false;
        }
        currentIndex++;
    }
    file.close();
}

void ListProcessesToFile(const char* filename) {
    // Create a handle to the snapshot of all processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating process snapshot. Exiting." << std::endl;
        return;
    }

    // Set the size of the structure before using it
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Open the process snapshot
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Error getting first process. Exiting." << std::endl;
        CloseHandle(hProcessSnap);
        return;
    }

    // Open the file for writing
    std::ofstream outFile(filename);

    if (!outFile.is_open()) {
        std::cerr << "Error opening file. Exiting." << std::endl;
        CloseHandle(hProcessSnap);
        return;
    }

    // Use a set to keep track of unique process names
    std::set<std::string> uniqueProcessNames;

    // Write process names to the file
    do {
        if (pe32.th32ProcessID > 4) {
            std::string processName = pe32.szExeFile;

            // Check if the process name is not already in the set
            if (uniqueProcessNames.insert(processName).second) {
                outFile << processName << std::endl;
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    // Close handles
    CloseHandle(hProcessSnap);
    outFile.close();
}

void RunFunctionPeriodically() {

    const char* filename = "C:\\APPAIEtwLogger\\processes.txt";
    ListProcessesToFile(filename);

    while (true) {

        LoadProcessNames();
        randomString = generateRandomString(8);
        // Sleep for 5 minutes (300 seconds)
        std::this_thread::sleep_for(std::chrono::seconds(60));
        ListProcessesToFile(filename);
    }
}

//void LoadVectorizer() {
//    std::ifstream file("vectorizer_tfidf.pickle.dat", std::ios::binary);
//
//    if (!file.is_open()) {
//
//        std::cerr << "Error opening file." << std::endl;
//        std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
//        }
//
//}

int initEtwMon() {
    DBG_LOG("Init EtwMon called...");
    InitializeCriticalSectionForFile();
    InitializeCriticalSectionForLog();
    std::thread periodicThread(RunFunctionPeriodically);
    periodicThread.detach();

    //LoadVectorizer();
    //MyVectorizer myVectorizer = ;
    //{
    //    boost::archive::binary_iarchive archive(file);
    //    archive >> myVectorizer;
    //}

    // Visualize the vectorizer's contents
    //myVectorizer.visualize();

    EtwMon monitor(EtwAgentName, EtwMon::LogDefault, EtwAlertProcessor);
    
    std::ifstream file("C:\\APPAIEtwLogger\\providers.txt");
    std::vector<std::wstring> lines;

    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            // Convert each line to wstring
            std::wstring wline(line.begin(), line.end());
            lines.push_back(wline);
        }
        file.close();
    }
    else {
        std::cerr << "Unable to open file" << std::endl;
        return 1;
    }

    std::vector<EtwMon::PROVIDER_INFO> providerInfoVector;

    for (const auto& line : lines) {
        EtwMon::PROVIDER_INFO curProviderInfo;
        size_t spacePos = line.find(L' ');
        curProviderInfo.providerName = line.substr(0, spacePos);

        // If there's a space, parse the event IDs
        if (spacePos != std::wstring::npos) {
            std::wstring eventIDsString = line.substr(spacePos + 1);
            auto eventIDs = EtwUtils::split(eventIDsString, L',');
            for (const auto& idStr : eventIDs) {
                curProviderInfo.eventIds.push_back(std::stoi(idStr));
            }
        }

        curProviderInfo.callback = [&monitor](const EVENT_RECORD& record, const krabs::trace_context& context) {
            monitor.cb_OnGenericEvent(record, context);
        };
        curProviderInfo.accesMasks = {};
        curProviderInfo.traceLevel = TRACE_LEVEL_VERBOSE;

        providerInfoVector.emplace_back(curProviderInfo);
    }

    // Print provider names for verification
    for (const auto& provider : providerInfoVector) {
        std::wcout << L"Provider: " << provider.providerName << L", Event IDs: ";
        for (const auto id : provider.eventIds) {
            std::wcout << id << L" ";
        }
        std::wcout << std::endl;
    }

    if (monitor.RegisterProviders(providerInfoVector))
    {
        std::thread printerThread(printMapPeriodically);
        std::thread processJsonThread(ProcessJsonList);
        printerThread.detach();
        processJsonThread.detach();
        monitor.start();
    }
    
    DeleteCriticalSectionForFile();
    DeleteCriticalSectionForLog();

    return 0;
}

void InitializeGlobalDirectory() {
    char buffer[MAX_PATH];
    DWORD dwRet = GetCurrentDirectoryA(MAX_PATH, buffer);
    if (dwRet > 0) {
        g_curDirectory = buffer;
        std::cout << "Current directory : " << g_curDirectory << std::endl;
    }
    else {
        std::cerr << "Failed to get current directory" << std::endl;
        g_curDirectory = "";
    }
}

int main() {
    g_logFileName = EtwUtils::getComputerName() + ".txt";
    g_curProcId = GetCurrentProcessId();
    InitializeGlobalDirectory();
    initEtwMon();
    return 0;
}