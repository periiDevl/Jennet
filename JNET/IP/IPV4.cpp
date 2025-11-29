#include"IPV4.h"
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
