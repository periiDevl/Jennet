
#pragma once
#include"Defng.h"
#include"IPV4_HEADER.h"
class Protocol
{
protected:
    virtual void calculateAndSetChecksum(IPV4_HEADER& header);
    virtual bytes_2 internetChecksum(const void* data, size_t length);
public:
    Protocol();
    ~Protocol();
};
