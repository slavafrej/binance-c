#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define EVP_MAX_MD_SIZE 32

unsigned char *mx_hmac_sha256(const void *key, int keylen,
                              const unsigned char *data, int datalen,
                              unsigned char *result, unsigned int *resultlen) {
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}


int main(){
    char *key = strdup("9lZXK2oilHxFXOsLnOk5vB5aARScL7EpGLg40EnFdl3dl4AHAhUmrWYOIKIrvxEy");
    int keylen = strlen(key);
    const unsigned char *data = (const unsigned char *)strdup("timestamp=1695472174000");
    int datalen = strlen((char *)data);
    unsigned char *result = NULL;
    unsigned int resultlen = -1;

    result = mx_hmac_sha256((const void *)key, keylen, data, datalen, result, &resultlen);

    for (unsigned int i = 0; i < resultlen; i++) 
        printf("%c", result[i]);

    printf("\n");
    for (unsigned int i = 0; i < resultlen; i++) 
        printf("%u ", result[i]);

    printf("\nencrypted: %s   len = %d\n", result, resultlen);
    for (unsigned int i = 0; i < resultlen; i++){
        printf("%02hhX", result[i]); // or just "%02X" if you are not using C11 or later
    }
}