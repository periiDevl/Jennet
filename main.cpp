#include <QApplication>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWidget>
#include <QTimer>
#include "Sniffer.h"
#include"UI/PacketInfo.h"
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    QWidget window;
    PacketInfo pktInf(&window);
    
    QVBoxLayout layout(&window);

    Sniffer sniffer(&pktInf);
    if (!sniffer.openDefaultDevice()) {
        return 1;
    }
    QTimer timer;
    QObject::connect(&timer, &QTimer::timeout, [&]() {
        sniffer.start();
    });
    timer.start(500);

    

    window.resize(600, 400);
    window.show();
    int result = app.exec();
    //sniffer.stop();
    return result;
}
