#include"Handler.h"
const char* Handler::getInterface(){return interface;}
Handler::Handler(const char* interf)
{
    interface = interf;
    const char* iface = "wlo1";
    char errbuf[PCAP_ERRBUF_SIZE]{};

    handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        throw std::runtime_error("pcap_open_live failed");
    }
}

Handler::~Handler()
{
}
void Handler::close(){
    pcap_close(handle);
}
pcap_t* Handler::get()
{
    return handle;
}