#include<iostream>
#include"IP/IPV4.h"
int main(){
    IPV4_HEADER header{};

    header.Hchecksum = 0;
    IPV4 ipv;
    
    header.Hchecksum = ipv.checksum();

}