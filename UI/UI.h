#pragma once
#include <QApplication>
#include <QMainWindow>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QString>
#include <QWidget>

void displayText(QWidget *parent, const QString &text, int x, int y, int width, int height) {
    QLabel *label = new QLabel(text, parent);
    label->move(x, y);
    label->resize(width, height);
    label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    label->show();
}
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
    vLine->setLineWidth(2);
    vLine->setMidLineWidth(1);
    vLine->move(x, y);
    vLine->resize(2, height);
    vLine->show();
}