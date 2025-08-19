#pragma once
#include"pcap.h"
#include"string"
#include"iostream"
class Handler
{
private:
    const char* interface;
    pcap_t* handle;
public:
    Handler(const char* interf);
    ~Handler();
    const char* getInterface();
    pcap_t* get();
    void close();
};
