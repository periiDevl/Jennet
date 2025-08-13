
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <chrono>
#include <vector>
#include "Packet.h"
#include "IP/EthernetHeader.h"
#include "IP/IPV4.h"
#include "TCP/TCP.h"
#include "TCP/TCP_FLAGS.h"
#include "Testing.h"
#include "InternetUtils.h"
#include <cjson/cJSON.h>
#include"UI/UI.h"
char* read_file(const char* filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("Failed to open file");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (length < 0) {
        fclose(f);
        perror("ftell failed");
        return NULL;
    }
    char *buffer = (char*)malloc(length + 1);
    if (!buffer) {
        fclose(f);
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    size_t read_len = fread(buffer, 1, length, f);
    fclose(f);
    if (read_len != length) {
        free(buffer);
        fprintf(stderr, "Failed to read whole file\n");
        return NULL;
    }
    buffer[length] = '\0'; 
    return buffer;
}
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    QMainWindow mainWindow;
    mainWindow.setWindowTitle("Jennet - Jonathan Perii");
    mainWindow.setFixedSize(800, 500);

    QWidget *centralWidget = new QWidget(&mainWindow);

    displayText(&mainWindow, "Interface :", 10, 10, 300, 30);
    QLineEdit* InterfaceTextbox = createTextBox(centralWidget, 10, 40, 250, 30);
    
    displayText(&mainWindow, "Source IP", 10, 70 + 10, 300, 30);
    QLineEdit* srcIPTextbox = createTextBox(centralWidget, 10, 110, 250, 30);
    displayText(&mainWindow, "Source MAC (12 Hex digits)", 10, 140, 300, 30);
    QLineEdit* srcMACTextbox = createTextBox(centralWidget, 10, 170, 250, 30);
    
    displayText(&mainWindow, "Dst IP", 10, 200, 300, 30);
    QLineEdit* dstIPTextbox = createTextBox(centralWidget, 10, 230, 250, 30);
    
    displayText(&mainWindow, "Dst MAC (12 Hex digits)", 10, 270, 300, 30);
    QLineEdit* dstMACTextbox = createTextBox(centralWidget, 10, 300, 250, 30);
    
    // Button to submit
    QPushButton *submitButton = new QPushButton("Auto MAC?", centralWidget);
    submitButton->move(10, 340);
    submitButton->resize(80, 30);
    bool autoMAC = false;
    QObject::connect(submitButton, &QPushButton::clicked, [&]() {
        autoMAC = true;  // this runs when button is clicked
    });

    createVerticalLine(centralWidget, 270, 0, 500);  // x=100, y=20, height=200

    const char *filename = "JSONS/IPV4.json";
    char *json_text = read_file(filename);
    if (!json_text) {
        return 1;
    }
    cJSON *root = cJSON_Parse(json_text);
    free(json_text);



    /*
    if (!mg.getInterfaceMac(srcMac)) {
        std::cerr << "Failed to get source MAC address\n";
        handler.close();
        return 1;
    }

    if (!mg.getGatewayMac(dstMac)) {
        std::cerr << "Failed to get gateway MAC address\n";
        handler.close();
        return 1;
    }
    */


    QPushButton* sendButton = new QPushButton("Send Packet", centralWidget);
    sendButton->move(120, 340);
    sendButton->resize(100, 30);

    QObject::connect(sendButton, &QPushButton::clicked, [&]() {
        Handler handler("enp11s0");
        MacGetter mg(handler.getInterface());
        byte srcMac[6]{};
        byte dstMac[6]{};
        MacGetter::macFromLineEdit(srcMACTextbox, srcMac);
        MacGetter::macFromLineEdit(dstMACTextbox, dstMac);
        TCP tcp;
        tcp.addSynOptions();
        const size_t tcpOptionsLen = tcp.payload.size();
        const size_t tcpHeaderLen = sizeof(TCP_HEADER) + tcpOptionsLen;

        const size_t totalPacketSize = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + tcpHeaderLen;
        Packet pkt(totalPacketSize);

        ETHERNET_HEADER* eth = reinterpret_cast<ETHERNET_HEADER*>(pkt.packet);
        memcpy(eth->srcMac, srcMac, 6);
        memcpy(eth->dstMac, dstMac, 6);
        eth->ethernetType = convertToBigEndian16(0x0800);
        pkt.reserve(sizeof(ETHERNET_HEADER));

        IPV4 ipv4;
        ipv4.include(pkt);
        ipv4.header->version_IHL = (4 << 4) | (sizeof(IPV4_HEADER) / 4);
        ipv4.header->TOS = 0;
        ipv4.header->totalLen = convertToBigEndian16(sizeof(IPV4_HEADER) + tcpHeaderLen);
        ipv4.header->id = convertToBigEndian16(0x1234);
        ipv4.header->flags_fragmentOffset = convertToBigEndian16(0x4000);
        ipv4.header->TTL = 64;
        ipv4.header->protocol = 6;
        QString srcIPQString = srcIPTextbox->text().trimmed();
        QString dstIPQString = dstIPTextbox->text().trimmed();

        std::string srcIPStr = srcIPQString.toStdString();
        std::string dstIPStr = dstIPQString.toStdString();

        ipv4.header->sendersIP = convertToBigEndian32(v4addr(srcIPStr));
        ipv4.header->reciveIP = convertToBigEndian32(v4addr(dstIPStr));
        ipv4.applyChecksum();
        pkt.reserve(sizeof(IPV4_HEADER));

        tcp.include(pkt);
        pkt.reserve(tcpHeaderLen);

        tcp.construtPrmtv(SYN());

        tcp.header->srcPort = convertToBigEndian16(52848);
        tcp.header->destPort = convertToBigEndian16(80);
        tcp.header->seqNum = convertToBigEndian32(static_cast<bytes_4>(1798999813));
        tcp.header->windowSize = convertToBigEndian16(64240);

        tcp.header->dataOffReservedAndNS = ((sizeof(TCP_HEADER) + tcpOptionsLen) / 4) << 4;

        memcpy(reinterpret_cast<byte*>(tcp.header + 1), tcp.payload.data(), tcp.payload.size());

        tcp.configurePseudoHeader(*ipv4.header);
        tcp.applyChecksum();


        if (pkt.send(handler) != 0) {
            std::cerr << "Failed to send packet\n";
            handler.close();
        } else {
            std::cout << "Packet sent successfully!\n";
        }
        std::cout << "SYN with correct TCP options sent to 1.1.1.1:80\n";

        handler.close();
    });

    
    mainWindow.setCentralWidget(centralWidget);
    mainWindow.show();

    return app.exec();
}
