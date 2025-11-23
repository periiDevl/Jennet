#pragma once
#include"JSON_JENNET.h"
#include <cjson/cJSON.h>
#include<stdio.h>
#include<stdlib.h>
class AdressesCLI
{
private:
    JSON_JENNET jsonReader;
public:
    char* read(const char* filename);
    void load(const char* fileName);
    std::string interface;
    std::string srcIp;
    std::string dstIp;
    std::string srcMac;
    std::string dstMac;
    AdressesCLI();
    ~AdressesCLI();
};

