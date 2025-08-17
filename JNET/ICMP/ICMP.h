#pragma once
#include"ICMP_HEADER.h"
#include"Protocol.h"
class ICMP : public Protocol<ICMP_HEADER>
{
private:
public:
    inline ICMP();
    inline ~ICMP();
    inline void applyChecksum() override;
};

ICMP::ICMP()
{
}

ICMP::~ICMP()
{
}
void ICMP::applyChecksum()
{
    header->checksum = 0;
    header->checksum =  internetChecksum(header, sizeof(ICMP_HEADER));

}

