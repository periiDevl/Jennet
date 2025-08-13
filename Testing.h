#pragma once
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include"UI/UI.h"
using byte = unsigned char;
//NOT MY CODE TO IM REMOVING IT NEXT UPDATE
class MacGetter {
    const char* iface;

public:
    explicit MacGetter(const char* interfaceName) : iface(interfaceName) {}

    static bool macFromLineEdit(QLineEdit* edit, byte mac[6]) {
        if (!edit) return false;

        QString text = edit->text().trimmed();
        std::string macStr = text.toStdString();

        if (macStr.length() != 17) return false; // AA:BB:CC:DD:EE:FF format

        unsigned int vals[6];
        if (sscanf(macStr.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                   &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) != 6)
            return false;

        for (int i = 0; i < 6; ++i)
            mac[i] = static_cast<byte>(vals[i]);

        return true;
    }

    bool getInterfaceMac(byte srcMac[6]) const {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            perror("socket");
            return false;
        }
        struct ifreq ifr{};
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
            perror("ioctl");
            close(fd);
            return false;
        }
        close(fd);
        memcpy(srcMac, ifr.ifr_hwaddr.sa_data, 6);
        return true;
    }

    std::string getDefaultGatewayIP() const {
        std::ifstream routeFile("/proc/net/route");
        if (!routeFile.is_open()) {
            std::cerr << "Failed to open /proc/net/route\n";
            return {};
        }
        std::string line;
        while (std::getline(routeFile, line)) {
            std::istringstream iss(line);
            std::string iface, dest, gateway;
            iss >> iface >> dest >> gateway;
            if (iface == "Iface" || dest != "00000000") continue;

            unsigned long gw;
            std::stringstream ss;
            ss << std::hex << gateway;
            ss >> gw;

            struct in_addr gw_addr;
            gw_addr.s_addr = gw;
            return std::string(inet_ntoa(gw_addr));
        }
        return {};
    }

    static bool macStrToBytes(const std::string& macStr, byte mac[6]) {
        if (macStr.length() != 17) return false;
        unsigned int vals[6];
        if (sscanf(macStr.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                   &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) != 6)
            return false;
        for (int i = 0; i < 6; ++i) mac[i] = static_cast<byte>(vals[i]);
        return true;
    }

    bool getGatewayMac(byte dstMac[6]) const {
        std::string gwIP = getDefaultGatewayIP();
        if (gwIP.empty()) {
            std::cerr << "Cannot find default gateway IP\n";
            return false;
        }
        std::ifstream arpFile("/proc/net/arp");
        if (!arpFile.is_open()) {
            std::cerr << "Failed to open /proc/net/arp\n";
            return false;
        }
        std::string line;
        while (std::getline(arpFile, line)) {
            if (line.find(gwIP) != std::string::npos) {
                std::istringstream iss(line);
                std::string ip, hwType, flags, macStr, mask, device;
                iss >> ip >> hwType >> flags >> macStr >> mask >> device;
                if (macStrToBytes(macStr, dstMac)) {
                    return true;
                } else {
                    std::cerr << "Failed to parse MAC from ARP\n";
                    return false;
                }
            }
        }
        std::cerr << "Gateway MAC not found in ARP cache. Try pinging gateway first.\n";
        return false;
    }
};
