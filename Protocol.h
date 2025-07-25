
#pragma once
#include"Defng.h"
#include"IPV4_HEADER.h"
class Protocol
{
protected:
    virtual bytes_2 internetChecksum(const void* data, size_t length);
    virtual void applyChecksum();
public:
    Protocol();
    ~Protocol();
};
