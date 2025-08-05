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
    void construtPrmtv(byte flag);
    void addSynOptions();
    TCP_PSEUDO_HEADER psudoHeader;
    std::vector<byte> payload;
};

TCP::TCP()
{
}

TCP::~TCP()
{
}

void TCP::addSynOptions() {
    payload.clear();
    payload.reserve(20);

    payload.push_back(0x02);
    payload.push_back(0x04);
    payload.push_back(0x05);
    payload.push_back(0xB4);

    payload.push_back(0x04);
    payload.push_back(0x02);

    payload.push_back(0x08);
    payload.push_back(0x0A);
    
    uint32_t tsVal = convertToBigEndian32(static_cast<uint32_t>(4232487165));
    uint32_t tsEcho = 0;
    
    payload.insert(payload.end(), reinterpret_cast<byte*>(&tsVal), reinterpret_cast<byte*>(&tsVal) + 4);
    payload.insert(payload.end(), reinterpret_cast<byte*>(&tsEcho), reinterpret_cast<byte*>(&tsEcho) + 4);
    
    payload.push_back(0x01);

    payload.push_back(0x03);
    payload.push_back(0x03);
    payload.push_back(0x07);

    while (payload.size() < 20) {
        payload.push_back(0x00);
    }
}
void TCP::construtPrmtv(byte flag){
    header->seqNum = convertToBigEndian32(0x1);
    header->ackNum = 0;
    header->flag = flag;
    header->windowSize = convertToBigEndian16(65535);
    header->checksum = 0;
    header->urgPointer = 0;
}
void TCP::configurePseudoHeader(IPV4_HEADER& ipv4Header)
{
    psudoHeader.srcAddr = ipv4Header.sendersIP;
    psudoHeader.destAddr = ipv4Header.reciveIP;
    psudoHeader.zero = 0;
    psudoHeader.tcpLength = convertToBigEndian16(sizeof(*header) + payload.size());
    psudoHeader.protocol = 6;
}
void TCP::applyChecksum()
{
    header->checksum = 0;
    uint16_t tcpSegmentLen = sizeof(TCP_HEADER) + payload.size();

    psudoHeader.tcpLength = convertToBigEndian16(tcpSegmentLen);
    size_t totalLen = sizeof(TCP_PSEUDO_HEADER) + tcpSegmentLen;
    std::vector<byte> buffer(totalLen);

    std::memcpy(buffer.data(), &psudoHeader, sizeof(TCP_PSEUDO_HEADER));
    std::memcpy(buffer.data() + sizeof(TCP_PSEUDO_HEADER), header, sizeof(TCP_HEADER));

    if (!payload.empty()) {
        std::memcpy(buffer.data() + sizeof(TCP_PSEUDO_HEADER) + sizeof(TCP_HEADER), payload.data(), payload.size());
    }
    bytes_2 checksum = internetChecksumTCP(buffer.data(), totalLen);
    header->checksum = convertToBigEndian16(checksum);
}