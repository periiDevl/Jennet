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
#include <QComboBox>
#include <QDir>
#include <QInputDialog>  // <-- missing

int main(int argc, char *argv[]) {
    QString currentJsonFile = ""; 
    QApplication app(argc, argv);

    QMainWindow mainWindow;
    mainWindow.setWindowTitle("Jennet - Jonathan Perii");
    mainWindow.setFixedSize(800, 500);

    QWidget *centralWidget = new QWidget(&mainWindow);

    QLineEdit* InterfaceTextbox = createTextBox(centralWidget, 10, 40, 250, 30);
    QComboBox* interfaceDropdown = new QComboBox(centralWidget);
    interfaceDropdown->setGeometry(10, 40, 250, 30);

    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        QMessageBox::critical(nullptr, "Error", QString("Error finding devices: %1").arg(errbuf));
    } else {
        for (d = alldevs; d != nullptr; d = d->next) {
            if (d->name) {
                interfaceDropdown->addItem(d->name);
            }
        }
        pcap_freealldevs(alldevs);
    }

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
    jsonEditor->setText("{\nPlease load a JSON file from the /JSONS folder...\n}");

    QFile file("JSONS/SETTINGS.json");
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);
        jsonEditor->setText(in.readAll());
        file.close();
    }

    QPushButton* saveJsonButton = new QPushButton("Save JSON", centralWidget);
    saveJsonButton->setGeometry(280, 500 - 40, 100, 30);
    QComboBox* jsonFileDropdown = new QComboBox(centralWidget);
    jsonFileDropdown->setGeometry(380, 500 - 40, 200, 30);
    
    QObject::connect(saveJsonButton, &QPushButton::clicked, [&]() {
        QString filePath;

        if (currentJsonFile.isEmpty()) {
            QString newFileName = QInputDialog::getText(nullptr, "Save JSON", "Enter file name:");
            if (newFileName.isEmpty()) return;
            filePath = "JSONS/" + newFileName + ".json";
            currentJsonFile = filePath;
        } else {
            filePath = currentJsonFile;
        }

        QFile file(filePath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << jsonEditor->toPlainText();
            file.close();
            QMessageBox::information(nullptr, "Saved!", "File saved: " + filePath);
            QString shortName = filePath.mid(6);
            if (jsonFileDropdown->findText(shortName) == -1) {
                jsonFileDropdown->addItem(shortName);
            }
            jsonFileDropdown->setCurrentText(shortName);
        } else {
            QMessageBox::warning(nullptr, "Error", "Failed to save JSON file.");
        }
    });


    QPushButton* removeJsonButton = new QPushButton("Delete", centralWidget);
    removeJsonButton->setGeometry(680, 500 - 40, 100, 30);

    QObject::connect(removeJsonButton, &QPushButton::clicked, [&]() {
        QString fileName = jsonFileDropdown->currentText();
        if (fileName.isEmpty()) return;

        QString fullPath = "JSONS/" + fileName;
        if (QMessageBox::question(nullptr, "Delete JSON",
            "Are you sure you want to delete " + fileName + "?",
            QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {

            if (QFile::remove(fullPath)) {
                QMessageBox::information(nullptr, "Deleted", fileName + " removed.");
                int index = jsonFileDropdown->currentIndex();
                jsonFileDropdown->removeItem(index);
                jsonEditor->clear();
                currentJsonFile.clear();
            } else {
                QMessageBox::warning(nullptr, "Error", "Failed to delete " + fileName);
            }
        }
    });


    QDir jsonDir("JSONS");
    QStringList jsonFiles = jsonDir.entryList(QStringList() << "*.json", QDir::Files);
    jsonFileDropdown->addItems(jsonFiles);

    QObject::connect(jsonFileDropdown, &QComboBox::currentTextChanged, [&](const QString& fileName) {
        QFile file("JSONS/" + fileName);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&file);
            jsonEditor->setText(in.readAll());
            file.close();
            currentJsonFile = "JSONS/" + fileName;
        }
    });


    QPushButton* newJsonButton = new QPushButton("New JSON", centralWidget);
    newJsonButton->setGeometry(580, 500 - 40, 100, 30);

    QObject::connect(newJsonButton, &QPushButton::clicked, [&]() {
        jsonEditor->setText("{\n\t\"example\": \"new file\"\n}");
        currentJsonFile.clear();
        QMessageBox::information(nullptr, "New File", "New JSON created. Save to name it.");
    });


    QObject::connect(sendButton, &QPushButton::clicked, [&]() {
        QString selectedInterface = interfaceDropdown->currentText();
        Handler handler(selectedInterface.toStdString().c_str());

        MacGetter mg(handler.getInterface());

        byte srcMac[6]{}, dstMac[6]{};
        MacGetter::macFromLineEdit(srcMACTextbox, srcMac);
        MacGetter::macFromLineEdit(dstMACTextbox, dstMac);

        JSON_JENNET json;
        QString selectedJsonFile = jsonFileDropdown->currentText();
        json.loadFeatures(("JSONS/" + selectedJsonFile).toStdString().c_str());


        ETHERNET_HEADER eth{};
        std::memcpy(eth.srcMac, srcMac, 6);
        std::memcpy(eth.dstMac, dstMac, 6);
        eth.ethernetType = convertToBigEndian16(0x0800); // IPv4
        const std::string srcIPStr = srcIPTextbox->text().trimmed().toStdString();
        const std::string dstIPStr = dstIPTextbox->text().trimmed().toStdString();
        if (json.enableIPV4) {
            
            json.ipv4.header->sendersIP = convertToBigEndian32(v4addr(srcIPStr));
            json.ipv4.header->reciveIP  = convertToBigEndian32(v4addr(dstIPStr));
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
            eth.ethernetType = convertToBigEndian16(0x0806); //ARP
            json.arp.header->hardwareAdrssLen = 6;
            json.arp.header->protocolAdressLen = 4;
            memcpy(json.arp.header->sendAdrr, srcMac, 6);
            bytes_4 sendersIPbytes = convertToBigEndian32(v4addr(srcIPStr));
            memcpy(json.arp.header->sendProtolAdrr, &sendersIPbytes, 4);
            bytes_4 destIPbytes = convertToBigEndian32(v4addr(dstIPStr));
            memcpy(json.arp.header->reciveProtolAdrr, &destIPbytes, 4);
            if (json.arp.header->operation == 1) {
                memset(json.arp.header->reciveAdrr, 0, 6);
            } else {
                memcpy(json.arp.header->reciveAdrr, dstMac, 6);
            }
            
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
