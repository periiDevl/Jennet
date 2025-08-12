#include <QApplication>
#include <QMainWindow>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QString>
#include <QWidget>

// Function to display text at a given position and size
void displayText(QWidget *parent, const QString &text, int x, int y, int width, int height) {
    QLabel *label = new QLabel(text, parent);
    label->move(x, y); // Set position
    label->resize(width, height); // Set size
    label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    label->show();
}
// Function to create and display a QLineEdit, returns pointer so caller can get text later
QLineEdit* createTextBox(QWidget* parent, int x, int y, int width, int height) {
    QLineEdit* textBar = new QLineEdit(parent);
    textBar->move(x, y);
    textBar->resize(width, height);
    textBar->show();
    return textBar;
}
void createVerticalLine(QWidget* parent, int x, int y, int height) {
    QFrame* vLine = new QFrame(parent);
    vLine->setFrameShape(QFrame::VLine);
    vLine->setFrameShadow(QFrame::Sunken);
    vLine->setLineWidth(2);    // thickness
    vLine->setMidLineWidth(1);
    vLine->move(x, y);
    vLine->resize(2, height);  // fixed width=2, variable height
    vLine->show();
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

    createVerticalLine(centralWidget, 270, 0, 500);  // x=100, y=20, height=200


    mainWindow.setCentralWidget(centralWidget);
    mainWindow.show();

    return app.exec();
}
