#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QListWidget>
#include <QMessageBox>
#include <QDialog>
#include <QTextEdit>

#include <string>

class PacketInfo
{
private:
    QVBoxLayout* layout;
    QListWidget* listWidget;

public:
    PacketInfo(QWidget* window);
    ~PacketInfo();
    void add(const std::string &text, const std::string &info, int r, int g, int b);
};
