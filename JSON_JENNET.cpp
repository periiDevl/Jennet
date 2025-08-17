#include"JSON_JENNET.h"
JSON_JENNET::JSON_JENNET()
{
}

JSON_JENNET::~JSON_JENNET()
{
}
char* JSON_JENNET::read_file(const char* filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("Failed to open file");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (length < 0) {
        fclose(f);
        perror("ftell failed");
        return NULL;
    }
    char *buffer = (char*)malloc(length + 1);
    if (!buffer) {
        fclose(f);
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    size_t read_len = fread(buffer, 1, length, f);
    fclose(f);
    if (read_len != length) {
        free(buffer);
        fprintf(stderr, "Failed to read whole file\n");
        return NULL;
    }
    buffer[length] = '\0'; 
    return buffer;
}


void JSON_JENNET::loadFeatures(const char* filename) {
    char *json_text = read_file(filename);
    if (!json_text) {
        fprintf(stderr, "Failed to read JSON file\n");
        return;
    }

    cJSON *root = cJSON_Parse(json_text);
    if (!root) {
        fprintf(stderr, "Failed to parse JSON: %s\n", cJSON_GetErrorPtr());
        free(json_text);
        return;
    }
    
    cJSON *ipv4Json = cJSON_GetObjectItem(root, "IPV4");
    if (ipv4Json)
    {
        ipv4.header = new IPV4_HEADER;
        totalSize += sizeof(IPV4_HEADER);
        enableIPV4 = true;
        ipv4.header->version_IHL = (cJSON_GetObjectItem(ipv4Json, "version")->valueint << 4) |
                            (cJSON_GetObjectItem(ipv4Json, "IHL")->valueint & 0x0F);
        ipv4.header->TOS = cJSON_GetObjectItem(ipv4Json, "TOS")->valueint;
        ipv4.header->id = convertToBigEndian16(cJSON_GetObjectItem(ipv4Json, "id")->valueint);
        ipv4.header->flags_fragmentOffset = convertToBigEndian16(cJSON_GetObjectItem(ipv4Json,"flags")->valueint << 13 | cJSON_GetObjectItem(ipv4Json, "fragmentOffset")->valueint);
        ipv4.header->TTL = cJSON_GetObjectItem(ipv4Json, "TTL")->valueint;
        ipv4.header->protocol = cJSON_GetObjectItem(ipv4Json, "protocol")->valueint;
    }
    cJSON *tcpJson = cJSON_GetObjectItem(root, "TCP");
    if (tcpJson)
    {
        tcp.header = new TCP_HEADER;
        enableTCP = true;
        cJSON *tcpOptionsJson = cJSON_GetObjectItem(root, "TCP_OP");
        if (tcpOptionsJson)
        {
            tcp.addSynOptions(
                cJSON_GetObjectItem(tcpOptionsJson, "MSS")->valueint,
                cJSON_GetObjectItem(tcpOptionsJson, "WindowScale")->valueint,
                cJSON_GetObjectItem(tcpOptionsJson, "TSVal")->valueint,
                cJSON_GetObjectItem(tcpOptionsJson, "TSEcho")->valueint,
                cJSON_IsTrue(cJSON_GetObjectItem(tcpOptionsJson, "SACK"))
            );
        }
        cJSON *textTCP = cJSON_GetObjectItem(root, "TEXT");
        if (textTCP)
        {
            tcp.addText(cJSON_GetObjectItem(textTCP, "DATA")->valuestring);
        }
        totalSize += sizeof(TCP_HEADER) + tcp.payload.size();
        
        tcp.construtPrmtv(2);
        tcp.header->srcPort = convertToBigEndian16(cJSON_GetObjectItem(tcpJson, "srcPort")->valueint);
        tcp.header->destPort = convertToBigEndian16(cJSON_GetObjectItem(tcpJson, "dstPort")->valueint);
        tcp.header->seqNum = convertToBigEndian32(cJSON_GetObjectItem(tcpJson, "seqNum")->valueint);
        tcp.header->ackNum = convertToBigEndian32(cJSON_GetObjectItem(tcpJson, "ackNum")->valueint);
        tcp.header->windowSize = convertToBigEndian16(cJSON_GetObjectItem(tcpJson, "windowSize")->valueint);
        tcp.header->flag = cJSON_GetObjectItem(tcpJson, "flags")->valueint;
        tcp.header->urgPointer = convertToBigEndian16(cJSON_GetObjectItem(tcpJson, "urgPointer")->valueint);
        
        tcp.header->dataOffReservedAndNS = 
            (((sizeof(TCP_HEADER) + tcp.payload.size()) / 4) << 4) |
            ((cJSON_GetObjectItem(tcpJson, "reserved")->valueint & 0x07) << 1) |
            (cJSON_GetObjectItem(tcpJson, "NS")->valueint & 0x01);
        
        if (enableIPV4) {
            ipv4.header->totalLen = convertToBigEndian16(sizeof(IPV4_HEADER) + sizeof(TCP_HEADER) + tcp.payload.size());
            ipv4.applyChecksum();
        }
        tcp.configurePseudoHeader(*ipv4.header);
        tcp.applyChecksum();
    }
    cJSON *icmpJson = cJSON_GetObjectItem(root, "ICMP");
    if (icmpJson)
    {
        icmp.header = new ICMP_HEADER;
        totalSize += sizeof(ICMP_HEADER);
        enableICMP = true;

        icmp.header->type = cJSON_GetObjectItem(icmpJson, "type")->valueint;
        icmp.header->code = cJSON_GetObjectItem(icmpJson, "code")->valueint;
        bytes_2 id  = (bytes_2)cJSON_GetObjectItem(icmpJson, "id")->valueint;
        bytes_2 seq = (bytes_2)cJSON_GetObjectItem(icmpJson, "seq")->valueint;
        icmp.header->extendedHeader = convertToBigEndian32(((bytes_4)id << 16) | seq);
        ipv4.header->totalLen = convertToBigEndian16(sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER));
        icmp.applyChecksum();
    }
    cJSON_Delete(root);
    free(json_text);
}