#include <pcap.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <vector>
#include "Packet.h"
#include "IP/EthernetHeader.h"
#include "IP/IPV4.h"
#include "TCP/TCP.h"
#include "TCP/TCP_FLAGS.h"
#include "UI/UI.h"
#include "JSON_JENNET.h"
#include "Testing.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    QMainWindow mainWindow;
    mainWindow.setWindowTitle("Jennet - Jonathan Perii");
    mainWindow.setFixedSize(800, 500);

    QWidget *centralWidget = new QWidget(&mainWindow);

    displayText(&mainWindow, "Interface :", 10, 10, 300, 30);
    QLineEdit* InterfaceTextbox = createTextBox(centralWidget, 10, 40, 250, 30);

    displayText(&mainWindow, "Source IP", 10, 80, 300, 30);
    QLineEdit* srcIPTextbox = createTextBox(centralWidget, 10, 110, 250, 30);
    displayText(&mainWindow, "Source MAC (12 Hex digits)", 10, 140, 300, 30);
    QLineEdit* srcMACTextbox = createTextBox(centralWidget, 10, 170, 250, 30);

    displayText(&mainWindow, "Dst IP", 10, 200, 300, 30);
    QLineEdit* dstIPTextbox = createTextBox(centralWidget, 10, 230, 250, 30);
    displayText(&mainWindow, "Dst MAC (12 Hex digits)", 10, 270, 300, 30);
    QLineEdit* dstMACTextbox = createTextBox(centralWidget, 10, 300, 250, 30);

    QPushButton *submitButton = new QPushButton("Auto MAC?", centralWidget);
    submitButton->move(10, 340);
    submitButton->resize(80, 30);
    bool autoMAC = false;
    QObject::connect(submitButton, &QPushButton::clicked, [&]() { autoMAC = true; });

    createVerticalLine(centralWidget, 270, 0, 500);
    QPushButton* sendButton = new QPushButton("Send Packet", centralWidget);
    sendButton->move(120, 340);
    sendButton->resize(100, 30);

    QObject::connect(sendButton, &QPushButton::clicked, [&]() {
        Handler handler("enp11s0");
        MacGetter mg(handler.getInterface());

        byte srcMac[6]{}, dstMac[6]{};
        MacGetter::macFromLineEdit(srcMACTextbox, srcMac);
        MacGetter::macFromLineEdit(dstMACTextbox, dstMac);

        JSON_JENNET json;
        json.loadFeatures("JSONS/SETTINGS.json");

        ETHERNET_HEADER eth{};
        std::memcpy(eth.srcMac, srcMac, 6);
        std::memcpy(eth.dstMac, dstMac, 6);
        eth.ethernetType = convertToBigEndian16(0x0800); // IPv4

        if (json.enableIPV4) {
            const std::string srcIPStr = srcIPTextbox->text().trimmed().toStdString();
            const std::string dstIPStr = dstIPTextbox->text().trimmed().toStdString();
            json.ipv4.header->sendersIP = convertToBigEndian32(v4addr(srcIPStr));
            json.ipv4.header->reciveIP  = convertToBigEndian32(v4addr(dstIPStr));
        }

        const size_t tcpOptionsLen  = json.tcp.payload.size();
        const size_t tcpHeaderSize  = sizeof(TCP_HEADER) + tcpOptionsLen;
        const size_t totalPacketLen = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + tcpHeaderSize;
        json.ipv4.header->Hchecksum = 0;
        json.ipv4.applyChecksum();
        json.tcp.configurePseudoHeader(*json.ipv4.header);
        json.tcp.applyChecksum();

        Packet pkt(totalPacketLen);
        std::memcpy(pkt.packet, &eth, sizeof(ETHERNET_HEADER));
        std::memcpy(pkt.packet + sizeof(ETHERNET_HEADER), json.ipv4.header, sizeof(IPV4_HEADER));
        std::memcpy(pkt.packet + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER), json.tcp.header, sizeof(TCP_HEADER));

        if (tcpOptionsLen) {
            std::memcpy(
                pkt.packet + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(TCP_HEADER),
                json.tcp.payload.data(),
                tcpOptionsLen
            );
        }


        if (pkt.send(handler) != 0) {
            std::cerr << "Failed to send packet\n";
        } else {
            std::cout << "Packet sent successfully!\n";
        }
        std::cout << "SYN with correct TCP options sent\n";

        handler.close();
    });


    mainWindow.setCentralWidget(centralWidget);
    mainWindow.show();
    return app.exec();
}
