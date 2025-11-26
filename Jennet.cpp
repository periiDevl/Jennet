#include"Jennet.h"

Jennet::Jennet(const char* file1, const char* file2)
{
    adrCli.load(file1);

    MacGetter macGetter(adrCli.interface.c_str());

    std::array<byte, 6> srcMac = macGetter.stringToMac(adrCli.srcMac);
    std::array<byte, 6> dstMac = macGetter.stringToMac(adrCli.dstMac);

    ETHERNET_HEADER eth{};
    std::memcpy(eth.srcMac, srcMac.data(), 6);
    std::memcpy(eth.dstMac, dstMac.data(), 6);
    eth.ethernetType = convertToBigEndian16(0x0800); // make sure field name matches struct

    Handler handler(adrCli.interface.c_str());
    JSON_JENNET json;
    json.loadFeatures(file2);

    if (json.enableIPV4) {

        json.ipv4.header->sendersIP = convertToBigEndian32(v4addr(adrCli.srcIp));
        json.ipv4.header->reciveIP  = convertToBigEndian32(v4addr(adrCli.dstIp));
        json.ipv4.header->Hchecksum = 0;
        json.ipv4.applyChecksum();
    }
    if (json.enableTCP){
        json.tcp.configurePseudoHeader(*json.ipv4.header);
        json.tcp.applyChecksum();
    }
    if (json.enableARP)
    {
        json.arp.header->protocolType = convertToBigEndian16(0x0800);
        eth.ethernetType = convertToBigEndian16(0x0806); // ARP
        json.arp.header->hardwareAdrssLen = 6;
        json.arp.header->protocolAdressLen = 4;
        std::memcpy(json.arp.header->sendAdrr, srcMac.data(), 6);
        bytes_4 sendersIPbytes = convertToBigEndian32(v4addr(adrCli.srcIp));
        std::memcpy(json.arp.header->sendProtolAdrr, &sendersIPbytes, 4);
        bytes_4 destIPbytes = convertToBigEndian32(v4addr(adrCli.dstIp));
        std::memcpy(json.arp.header->reciveProtolAdrr, &destIPbytes, 4);
        if (json.arp.header->operation == 1) {
            memset(eth.dstMac, 0xFF, 6);
        }
    }
    if (json.enableUDP){
        json.udp.configurePseudoHeader(*json.ipv4.header);
        json.udp.applyChecksum();
    }
    Packet pkt(json.totalSize + sizeof(ETHERNET_HEADER));
    json.consturct(&pkt, eth);

    if (pkt.send(handler) != 0) {
        std::cerr << "Failed to send packet\n";
    } else {
        std::cout << "Packet sent successfully!\n";
    }

    handler.close();
}


Jennet::~Jennet()
{
}
