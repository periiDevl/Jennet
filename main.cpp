#include<iostream>
#include"IP/IPV4.h"
#include"include/pcapplusplus/ArpLayer.h"
int main(){
    pcpp::IPv4Address myIp("127.0.0.1"); 

    /*
    IPV4_HEADER header{};

    header.Hchecksum = 0;
    IPV4 ipv;
    
    header.Hchecksum = ipv.checksum();
    */
   std::cout << "Hello im Jennet" << std::endl;
   const char* device = "eth0";

}
