#include "PacketInfo.h"

PacketInfo::PacketInfo(QWidget* window)
{
    layout = new QVBoxLayout(window);
    listWidget = new QListWidget(window);
    layout->addWidget(listWidget);
    
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
