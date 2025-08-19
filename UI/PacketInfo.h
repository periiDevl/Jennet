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
    PacketInfo(QWidget* parent);
    ~PacketInfo();
    void add(const std::string &text, const std::string &info, int r, int g, int b);
    void setPosAndSize(int x, int y, int width, int height);
    void clear();
};
