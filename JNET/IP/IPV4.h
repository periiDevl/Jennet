#pragma once
#include"IPV4_HEADER.h"
#include"Protocol.h"
class IPV4 : public Protocol<IPV4_HEADER>
{
private:


public:
    
    IPV4();
    ~IPV4();
    void applyChecksum() override;
};

IPV4::IPV4()
{
}

IPV4::~IPV4()
{
}
void IPV4::applyChecksum()
{
    header->Hchecksum = 0;
    header->Hchecksum = internetChecksum(header, sizeof(IPV4_HEADER));
    //header->Hchecksum = internetChecksum(header, sizeof(header));
}
