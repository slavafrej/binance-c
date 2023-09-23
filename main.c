/*
Binance-C

by slavafrej
2023
*/
#include <sys/time.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define EVP_MAX_MD_SIZE 32


long int timeStamp(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double st = tv.tv_sec * 1.0 + tv.tv_usec / 1000000.0;
    long int timestamp = (long int)st * 1000;
    return timestamp;
}

unsigned char *mx_hmac_sha256(const void *key, int keylen,
                              const unsigned char *data, int datalen,
                              unsigned char *result, unsigned int *resultlen) {
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}

void sendNotification(char* text){
    char* command;
    char title[8] = "Traders";
    sprintf(command, "notify-send %s %s", title, text);
    system(command);
}

size_t static write_callback_func(void *buffer, size_t size, size_t nmemb, void *userp)
{
    char **response_ptr =  (char**)userp;
    *response_ptr = strndup(buffer, (size_t)(size *nmemb));
}

char *generateSignature(const char *secret, const char *raw){
    char *key = strdup(secret);
    int keylen = strlen(key);
    const unsigned char *data = (const unsigned char *)strdup(raw);
    int datalen = strlen((char *)data);
    unsigned char *result = NULL;
    unsigned int resultlen = -1;
    char str[64];

    result = mx_hmac_sha256((const void *)key, keylen, data, datalen, result, &resultlen);

    sprintf(str, "%02hhX", result[0]);
    for (unsigned int i = 1; i < resultlen; i++){
        sprintf(str + strlen(str), "%02hhX", result[i]);
    }
    return strdup(str);
}

char* getRequest(char str[], char *h)  // make get request
{
    CURL *curl;
    CURLcode res;

    char* response;
    curl = curl_easy_init();
    struct curl_slist *list = NULL;
    
    if(curl) {
        list = curl_slist_append(list, h);
        curl_easy_setopt(curl, CURLOPT_URL, str);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
        res = curl_easy_perform(curl);
        curl_slist_free_all(list);
        curl_easy_cleanup(curl);
    }
    return response;
}

struct Binance
{
    char *API_KEY;
    char *API_SECRET;
    char *BASE_URL;
};

void getFuturesBalance(char *api, char *secret){
    char header[128] = "X-MBX-APIKEY: ";
    char *params[24];
    char signature[128];
    char endpoint[256] = "https://fapi.binance.com/fapi/v2/balance?";
    sprintf(params, "timestamp=%ld", timeStamp());
    char *sign = generateSignature(secret, params);
    strcat(endpoint, params);
    sprintf(signature, "&signature=%s", sign);
    strcat(endpoint, signature);
    strcat(header, api);
    free(sign);
    printf(getRequest(endpoint, header));
}

int main(){
    struct Binance myAcc = {"", "", "https://fapi.binance.com"};
    getFuturesBalance(myAcc.API_KEY, myAcc.API_SECRET);
    return 0;
}