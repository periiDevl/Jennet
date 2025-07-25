#include "IPV4.h"
void IPV4::applyChecksum()
{
    header.Hchecksum = 0;
    header.Hchecksum = internetChecksum(&header, sizeof(header));
}

