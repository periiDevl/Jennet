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
#include <QApplication>
#include <QMainWindow>
#include <QDockWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>


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

    QTextEdit* jsonEditor = new QTextEdit(centralWidget);
    jsonEditor->setGeometry(280, 10, 500, 480);
    jsonEditor->setText("{\n\t\"example\": \"edit me\"\n}");

    QFile file("JSONS/SETTINGS.json");
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);
        jsonEditor->setText(in.readAll());
        file.close();
    }

    QPushButton* saveJsonButton = new QPushButton("Save JSON", centralWidget);
    saveJsonButton->setGeometry(280, 500 - 40, 100, 30);

    QObject::connect(saveJsonButton, &QPushButton::clicked, [jsonEditor]() {
        QFile file("JSONS/SETTINGS.json");
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << jsonEditor->toPlainText();
            file.close();
            QMessageBox::information(nullptr, "Saved!", "Settings saved!");
        } else {
            QMessageBox::warning(nullptr, "Error", "Failed to save JSON file.");
        }
    });

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
            json.ipv4.header->Hchecksum = 0;
            json.ipv4.applyChecksum();
        }
        if (json.enableTCP){
            json.tcp.configurePseudoHeader(*json.ipv4.header);
            json.tcp.applyChecksum();
        }
        Packet pkt(json.totalSize + sizeof(ETHERNET_HEADER));
        json.consturct(&pkt, eth);

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
