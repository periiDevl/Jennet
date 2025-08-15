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
    
    inline TCP();
    inline ~TCP();
    inline void applyChecksum() override;
    inline void configurePseudoHeader(IPV4_HEADER& ipv4Header);
    inline void construtPrmtv(byte flag);
    inline void addSynOptions(
    uint16_t mss = 1460, 
    byte windowScale = 0, 
    uint32_t tsVal = 0, 
    uint32_t tsEcho = 0,
    bool addSACK = true
);
    TCP_PSEUDO_HEADER psudoHeader;
    std::vector<byte> payload;
};

TCP::TCP()
{
}

TCP::~TCP()
{
}

void TCP::addSynOptions(
    uint16_t mss, 
    byte windowScale, 
    uint32_t tsVal, 
    uint32_t tsEcho,
    bool addSACK
) {
    payload.clear();
    payload.push_back(0x02);
    payload.push_back(0x04);
    payload.push_back(mss >> 8);
    payload.push_back(mss & 0xFF);

    if (windowScale > 0) {
        payload.push_back(0x03);
        payload.push_back(0x03);
        payload.push_back(windowScale);
    }
    payload.push_back(0x08);
    payload.push_back(0x0A); 
    uint32_t tsValBE = convertToBigEndian32(tsVal);
    uint32_t tsEchoBE = convertToBigEndian32(tsEcho);
    payload.insert(payload.end(), reinterpret_cast<byte*>(&tsValBE), reinterpret_cast<byte*>(&tsValBE) + 4);
    payload.insert(payload.end(), reinterpret_cast<byte*>(&tsEchoBE), reinterpret_cast<byte*>(&tsEchoBE) + 4);
    payload.push_back(0x01);
    if (addSACK) {
        payload.push_back(0x04);
        payload.push_back(0x02);
    }
    while (payload.size() % 4 != 0) {
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