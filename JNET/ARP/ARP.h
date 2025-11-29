#pragma once
#include"ARP_HEADER.h"
#include"Protocol.h"
class ARP : public Protocol<ARP_HEADER>
{
private:
public:
    ARP();
    ~ARP();
    void applyChecksum() override;
};

