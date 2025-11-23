#include"AdressesCLI.h"
AdressesCLI::AdressesCLI()
{
}

AdressesCLI::~AdressesCLI()
{
}

char* AdressesCLI::read(const char* filename)
{
    return jsonReader.read_file(filename);
}
void AdressesCLI::load(const char* filename)
{
    char* text = read(filename);
    if (!text){printf("Error! no file.."); return;}
    cJSON *root = cJSON_Parse(text);
    if (!root)
    {
        printf("Failed to parse.");
        free(text);
        return;
    }
    cJSON *json = cJSON_GetObjectItem(root, "Adresses");
    interface = cJSON_GetObjectItem(json, "interface")->valuestring;
    srcIp = cJSON_GetObjectItem(json, "srcIp")->valuestring;
    srcMac = cJSON_GetObjectItem(json, "srcMac")->valuestring;
    dstIp = cJSON_GetObjectItem(json, "dstIp")->valuestring;
    dstMac = cJSON_GetObjectItem(json, "dstMac")->valuestring;
    cJSON_Delete(root);
    free(text);
}