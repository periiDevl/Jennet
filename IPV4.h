#pragma once
#include"IPV4_HEADER.h"
#include"Protocol.h"
class IPV4 : public Protocol
{
private:


public:
    IPV4_HEADER header;
    
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
