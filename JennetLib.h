#pragma once
#include<iostream>
#include"EthernetHeader.h"
#include"InternetUtils.h"
#include"Packet.h"
namespace jnet_lib{
    ETHERNET_HEADER& addEthernet(Packet& pkt, const byte srcMac[6], const byte dstMac[6], uint16_t etherType = 0x0800)
    {
        ETHERNET_HEADER* eth = reinterpret_cast<ETHERNET_HEADER*>(pkt.packet);
        memcpy(eth->dstMac, dstMac, 6);
        memcpy(eth->srcMac, srcMac, 6);
        eth->ethernetType = convertToBigEndian16(etherType);
        pkt.reserve(sizeof(ETHERNET_HEADER));
        return *eth;
    }
    void simpleIPV4(
        IPV4& ivp4,
        const char* srcIP = "127.0.0.1",
        const char* dstIP = "127.0.0.1",
        uint16_t id = 0x1234,
        uint8_t TTL = 64,
        uint8_t protocol = 6
    )
    {
        ivp4.header->version_IHL = (4 << 4) | (sizeof(IPV4_HEADER) / 4);
        ivp4.header->TOS = 0;
        ivp4.header->totalLen = convertToBigEndian(sizeof(IPV4_HEADER) + sizeof(TCP_HEADER));
        ivp4.header->id = convertToBigEndian(id);
        ivp4.header->flags_fragmentOffset = 0;
        ivp4.header->TTL = TTL;
        ivp4.header->protocol = protocol;
        ivp4.header->sendersIP = v4addr(srcIP);
        ivp4.header->reciveIP = v4addr(dstIP);

        ivp4.applyChecksum();
    }

  

}
