#include"Terminal.h"
Terminal::Terminal()
{
}

Terminal::~Terminal()
{
}
void Terminal::start(){
    printAscii();
    printf("\033[32m");
    printf("Hello welcome to JENNET here you will build you custom packets.\n");
    printf("~This program was made by Jonathan Peri~\n");
    printf("start by creating a custom packet by creating a .jnet file and load it\n");
    printf("newpkt - Create JNET file\n");
    printf("pkt - Open packet JNET file, by path or index\n");
    printf("ls - List packet JNET files\n");
    printf("\033[0m");
}