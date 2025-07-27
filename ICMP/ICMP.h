#pragma once
#include"ICMP_HEADER.h"
#include"Protocol.h"
class ICMP : public Protocol<ICMP_HEADER>
{
private:
public:
    ICMP();
    ~ICMP();
    void applyChecksum() override;
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
    header->checksum = internetChecksum(header, sizeof(ICMP_HEADER));

}

