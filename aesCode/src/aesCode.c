#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "SslWrap.h"

int main(int argc, char** argv) {
	SSL_OUTPUT_BUF *pEncry = NULL;
	SSL_OUTPUT_BUF *pClear = NULL;
    // check usage
    if (argc != 2) {
        fprintf(stderr, "%s <plain text>\n", argv[0]);
        exit(-1);
    }
    printf("%s\n\r", argv[1]);
    pEncry = SSL_WRAP_AES_Encry(argv[1], strlen(argv[1])+1);
    pClear = SSL_WRAP_AES_Dencry(pEncry->_pData, pEncry->_size);

    _SSL_WRAP_ResultPrint(pEncry);
    _SSL_WRAP_ResultPrint(pClear);
    printf("%s\n\r", (char*)pClear->_pData);

    return 0;
}
