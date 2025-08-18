#pragma once
#include"ARP_HEADER.h"
#include"Protocol.h"
class ARP : public Protocol<ARP_HEADER>
{
private:
public:
    inline ARP();
    inline ~ARP();
    inline void applyChecksum() override;
};

ARP::ARP()
{
}

ARP::~ARP()
{
}
void ARP::applyChecksum()
{
    printf("There is no checksum in ARP protocol\n");
}

