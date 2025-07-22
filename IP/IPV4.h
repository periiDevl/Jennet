#pragma once
#include"IPV4_HEADER.h"
class IPV4
{
private:
    bytes_2 checksum();

public:
    IPV4();
    ~IPV4();
};

IPV4::IPV4()
{
}

IPV4::~IPV4()
{
}
