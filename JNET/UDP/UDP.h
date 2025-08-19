#pragma once
#include"IP/IPV4.h"
#include"UDP_HEADER.h"
#include"vector"
#include <cstring>
class UDP : public Protocol<UDP_HEADER> 
{
private:
public:
    inline UDP();
    inline ~UDP();
    inline void addPayload(const std::vector<byte>& data);
    inline void addText(const std::string& text);
    inline void configurePseudoHeader(IPV4_HEADER& ipv4Header);
    inline void applyChecksum();
    UDP_PSEUDO_HEADER pseudoHeader;
    std::vector<byte> payload;
};

UDP::UDP()
{
}

UDP::~UDP()
{
}
void UDP::configurePseudoHeader(IPV4_HEADER& ipv4Header)
{
    pseudoHeader.srcAdrr = ipv4Header.sendersIP;
    pseudoHeader.dstAdrr = ipv4Header.reciveIP;
    pseudoHeader.zero = 0;
    pseudoHeader.protocol = 17;

    uint16_t len = sizeof(UDP_HEADER) + payload.size();
    pseudoHeader.udpLen = convertToBigEndian16(len);
    header->len = convertToBigEndian16(len);
}

void UDP::addText(const std::string& text) {
    payload.clear();
    payload.insert(payload.end(), text.begin(), text.end());
}
void UDP::addPayload(const std::vector<byte>& data)
{
    payload = data;
}

void UDP::applyChecksum() {
    header->checksum = 0;
    size_t udpSegmentLen = sizeof(UDP_HEADER) + payload.size();
    pseudoHeader.udpLen = convertToBigEndian16(udpSegmentLen);
    
    size_t totalLen = sizeof(UDP_PSEUDO_HEADER) + udpSegmentLen;
    std::vector<byte> buffer(totalLen);

    std::memcpy(buffer.data(), &pseudoHeader, sizeof(UDP_PSEUDO_HEADER));
    std::memcpy(buffer.data() + sizeof(UDP_PSEUDO_HEADER), header, sizeof(UDP_HEADER));

    if (!payload.empty()) {
        std::memcpy(buffer.data() + sizeof(UDP_PSEUDO_HEADER) + sizeof(UDP_HEADER),
                    payload.data(), payload.size());
    }

    header->checksum = convertToBigEndian16(internetChecksumTCP(buffer.data(), totalLen));
}