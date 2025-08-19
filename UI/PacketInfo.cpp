#include "PacketInfo.h"

PacketInfo::PacketInfo(QWidget* parent)
{
    listWidget = new QListWidget(parent);
    
    listWidget->setFocusPolicy(Qt::WheelFocus);
    listWidget->setAttribute(Qt::WA_AcceptTouchEvents);
    listWidget->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    listWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    listWidget->setEnabled(true);
    listWidget->setVisible(true);
    
    QObject::connect(listWidget, &QListWidget::itemDoubleClicked, [=](QListWidgetItem* item){
        QDialog* dialog = new QDialog();
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setWindowTitle("Packet Info");
        QVBoxLayout* layout = new QVBoxLayout(dialog);
        QTextEdit* textEdit = new QTextEdit(dialog);
        textEdit->setReadOnly(true);
        textEdit->setText(item->data(Qt::UserRole).toString());
        layout->addWidget(textEdit);
        dialog->resize(600, 400);
        dialog->show();
    });
}

PacketInfo::~PacketInfo()
{
}

void PacketInfo::add(const std::string &text, const std::string &info, int r, int g, int b)
{
    QListWidgetItem* item = new QListWidgetItem(QString::fromStdString(text));
    item->setData(Qt::UserRole, QString::fromStdString(info));
    item->setBackground(QBrush(QColor(r, g, b)));
    listWidget->addItem(item);
    
}

void PacketInfo::setPosAndSize(int x, int y, int width, int height)
{
    listWidget->setGeometry(x, y, width, height);
    listWidget->raise();
    listWidget->show();
}
void PacketInfo::clear()
{
    listWidget->clear();
}