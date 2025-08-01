#pragma once
#include"IP/IPV4.h"
#include"TCP_HEADER.h"
#include"Protocol.h"
#include"InternetUtils.h"
#include<vector>
class TCP : public Protocol<TCP_HEADER>
{
private:


public:
    
    TCP();
    ~TCP();
    void applyChecksum() override;
    void configurePseudoHeader(IPV4_HEADER& ipv4Header);
    TCP_PSEUDO_HEADER psudoHeader;
    std::vector<byte> payload;
};

TCP::TCP()
{
}

TCP::~TCP()
{
}
void TCP::configurePseudoHeader(IPV4_HEADER& ipv4Header)
{
    psudoHeader.srcAddr = ipv4Header.sendersIP;
    psudoHeader.destAddr = ipv4Header.reciveIP;
    psudoHeader.zero = 0; //Did not expect that
    psudoHeader.tcpLength = convertToBigEndian(sizeof(*header) + payload.size());
    psudoHeader.protocol = 6;
}
void TCP::applyChecksum()
{
    header->checksum = 0;
    size_t bothLen = static_cast<size_t>(psudoHeader.tcpLength) + sizeof(psudoHeader);
    if (!isMachineBigEndian()) {bothLen = static_cast<size_t>(switchbo16(psudoHeader.tcpLength)) + sizeof(psudoHeader);}
    byte* byteArr = new byte[bothLen];
    std::memcpy(byteArr, &psudoHeader, sizeof(psudoHeader));
    std::memcpy(byteArr + sizeof(psudoHeader), header, sizeof(*header));
    if (!payload.empty())
    {
        std::memcpy(byteArr + sizeof(psudoHeader) + sizeof(*header), payload.data(), payload.size());
    }
    bytes_2 checksum = internetChecksum(byteArr, bothLen);
    header->checksum = convertToBigEndian(checksum);
    delete[] byteArr; //Thank god people make me remember to free
}