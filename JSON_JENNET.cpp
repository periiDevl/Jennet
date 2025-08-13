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


void JSON_JENNET::loadFeatures(const char* filename, Packet* packt) {
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
    bytes_2 totalSize = 0;
    cJSON *ipv4Json = cJSON_GetObjectItem(root, "IPV4");
    if (ipv4Json)
    {
        totalSize += sizeof(IPV4_HEADER);
        enableIPV4 = true;
        ipv4.include(*packt);
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
        enableTCP = true;
        tcp.addSynOptions();
        totalSize += sizeof(TCP_HEADER) + tcp.payload.size();
        
    }

    // Process the JSON data as needed
    // ...
    /*
        ipv4.header->totalLen = convertToBigEndian16(sizeof(IPV4_HEADER) + tcpHeaderLen);
    */
    cJSON_Delete(root);
    free(json_text);
}