#pragma once
#include <pcap.h>
#include "UI/PacketInfo.h"
#include "InternetUtils.h"
#include <thread>
#include <atomic>

class Sniffer {
public:
    explicit Sniffer(PacketInfo* pktInfoPtr);
    ~Sniffer();
    bool openDefaultDevice();
    void start();
    void stop();
    bool isRunning() const { return running; }

private:
    static void packetHandler(u_char* args, const pcap_pkthdr* header, const u_char* packet);
    void captureLoop();
    
    pcap_t* handle;
    PacketInfo* pktInfo;
    std::thread captureThread;
    std::atomic<bool> running;
    std::atomic<bool> shouldStop;
};
