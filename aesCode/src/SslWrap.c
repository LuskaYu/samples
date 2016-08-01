/**************************************************************************//**
*
*                  版权所有 (C), 1999-2013, 
*
* @file SslWrap.c
* @brief
* @version 初稿
* @author yuch
* @date 2016年04月26日
* @note history:
*     @note    date:      2016年04月26日
*     @note    author:    yuch
*     @note    content:   新生成函数
******************************************************************************/


/*
 * 包含头文件
 */
#include "SslWrap.h"
/*
 * 宏定义
 */

/*
 * 外部变量说明
 */

/*
 * 外部函数原型说明
 */

/*
 * 全局变量
 */

/*
 * 模块级变量
 */

/*
 * 接口声明
 */



/**************************************************************************//**
* function: _SSL_WRAP_OBMalloc
* @brief
* @param  unsigned int len,
* @return
* @retval SSL_OUTPUT_BUF *
*
* @note history:
*     @note    date:      2016年04月26日
*     @note    author:    yuch
*     @note    content:   新生成函数
******************************************************************************/
SSL_OUTPUT_BUF *_SSL_WRAP_OBMalloc(unsigned int len)
{
	size_t  alignSize = 0;
	SSL_OUTPUT_BUF *pBuff = NULL;

	if (0 == len)
		return NULL;


	if (len % AES_BLOCK_SIZE == 0)
	{
		alignSize = len;
	}
	else
	{
		alignSize = (len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
	}

	pBuff = (SSL_OUTPUT_BUF *)calloc(sizeof(SSL_OUTPUT_BUF), sizeof(unsigned char));

	if (NULL == pBuff)
		return NULL;

	pBuff->_pData = (unsigned char*)calloc(alignSize, sizeof(unsigned char));
	pBuff->_size = alignSize;

	return pBuff;

}
/**************************************************************************//**
* function: _SSL_WRAP_AES_AlignMallocAndCopy
* @brief
* @param  unsigned char *pData,
* @param  unsigned int len,
* @return
* @retval SSL_OUTPUT_BUF *
*
* @note history:
*     @note    date:      2016年04月26日
*     @note    author:    yuch
*     @note    content:   新生成函数
******************************************************************************/
void _SSL_WRAP_OBCopy(SSL_OUTPUT_BUF *pDst, unsigned char *pSrc, unsigned int len)
{
	if ((NULL == pDst) || (NULL == pSrc) || (0 == len))
		return;

	if (len > pDst->_size)
		len = pDst->_size;


	memcpy((void*)pDst->_pData, (void*)pSrc, len);

}

/**************************************************************************//**
* function: _SSL_WRAP_AES_AlignFree
* @brief
* @param  SSL_OUTPUT_BUF *pData,
* @return
* @retval void
*
* @note history:
*     @note    date:      2016年04月26日
*     @note    author:    yuch
*     @note    content:   新生成函数
******************************************************************************/
void _SSL_WRAP_OBFree(SSL_OUTPUT_BUF *pData)
{

	if (NULL != pData)
	{
		if (pData->_pData != NULL)
			free(pData->_pData);
		free(pData);
	}
}

/**************************************************************************//**
* function: _SSL_WRAP_ResultPrint
* @brief
* @param  SSL_OUTPUT_BUF *pData,
* @return
* @retval void
*
* @note history:
*     @note    date:      2016年04月26日
*     @note    author:    yuch
*     @note    content:   新生成函数
******************************************************************************/
void _SSL_WRAP_ResultPrint(SSL_OUTPUT_BUF *pData)
{
	unsigned char* pBuf = pData->_pData;
	int i = 0;
	if (NULL == pData)
	{
		printf("The data is invalid\n\r");
		return;
	}
	printf("-----------------------------\n\r");
	printf("Buffer Size : %u\n\r", pData->_size);
	printf("Data Len : %u\n\r", pData->_size);
    for (; i<pData->_size; i++)
    {
        printf("%x%x", (pBuf[i] >> 4) & 0xf,pBuf[i] & 0xf);
    }
	printf("\n\r-----------------------------\n\r");
}


/**************************************************************************//**
* function: SSL_WRAP_AES_Encry
* @brief
* @param  unsigned char *pSrc,
* @param  unsigned int uiLen,
* @return
* @retval SSL_OUTPUT_BUF *
*
* @note history:
*     @note    date:      2016年04月26日
*     @note    author:    yuch
*     @note    content:   新生成函数
******************************************************************************/
SSL_OUTPUT_BUF * SSL_WRAP_AES_Encry(unsigned char *pSrc, unsigned int uiLen)
{
	AES_KEY aes;
	unsigned char iv[AES_BLOCK_SIZE];        // init vector
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16
    SSL_OUTPUT_BUF *pSrcOB = NULL;
    SSL_OUTPUT_BUF *pDstOB = NULL;
    int len = 0;
    int i = 0;
	if ((pSrc == NULL) || (0 == uiLen))
		return NULL;

	pSrcOB = _SSL_WRAP_OBMalloc(uiLen);
	if (NULL == pSrcOB)
		return NULL;

	_SSL_WRAP_OBCopy(pSrcOB, pSrc, uiLen);

	// Generate AES 128-bit key
	for (i=0; i<AES_BLOCK_SIZE; ++i)
	{
		key[i] = 32 + i;
	}

	// Generate AES 128-bit key
	for (i=0; i<AES_BLOCK_SIZE; ++i)
	{
		iv[i] = 0;
	}

	pDstOB = _SSL_WRAP_OBMalloc(pSrcOB->_size);
	if (NULL == pDstOB)
	{
    	goto SSL_WRAP_AES_DoEncry_ERROR_PROC;
	}

    if (AES_set_encrypt_key(key, 128, &aes) < 0) {
    	goto SSL_WRAP_AES_DoEncry_ERROR_PROC;
    }


     // encrypt (iv will change)
    AES_cbc_encrypt(pSrcOB->_pData, pDstOB->_pData, pSrcOB->_size, &aes, iv, AES_ENCRYPT);

    _SSL_WRAP_OBFree(pSrcOB);

    return pDstOB;

SSL_WRAP_AES_DoEncry_ERROR_PROC:
	_SSL_WRAP_OBFree(pSrcOB);
	_SSL_WRAP_OBFree(pSrcOB);
	return NULL;

}

/**************************************************************************//**
* function: SSL_WRAP_AES_Dencry
* @brief
* @param  unsigned char *pSrc,
* @param  unsigned int uiLen,
* @return
* @retval SSL_OUTPUT_BUF *
*
* @note history:
*     @note    date:      2016年04月26日
*     @note    author:    yuch
*     @note    content:   新生成函数
******************************************************************************/
SSL_OUTPUT_BUF * SSL_WRAP_AES_Dencry(unsigned char *pSrc, unsigned int uiLen)
{
	AES_KEY aes;
	unsigned char iv[AES_BLOCK_SIZE];        // init vector
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16
    SSL_OUTPUT_BUF *pSrcOB = NULL;
    SSL_OUTPUT_BUF *pDstOB = NULL;
    int len = 0;
    int i = 0;
	if ((pSrc == NULL) || (0 == uiLen))
		return NULL;

	pSrcOB = _SSL_WRAP_OBMalloc(uiLen);
	if (NULL == pSrcOB)
		return NULL;

	_SSL_WRAP_OBCopy(pSrcOB, pSrc, uiLen);

	// Generate AES 128-bit key
	for (i=0; i<AES_BLOCK_SIZE; ++i)
	{
		key[i] = 32 + i;
	}

	// Generate AES 128-bit key
	for (i=0; i<AES_BLOCK_SIZE; ++i)
	{
		iv[i] = 0;
	}

	pDstOB = _SSL_WRAP_OBMalloc(pSrcOB->_size);
	if (NULL == pDstOB)
	{
    	goto SSL_WRAP_AES_DeEncry_ERROR_PROC;
	}

    if (AES_set_decrypt_key(key, 128, &aes) < 0) {
    	goto SSL_WRAP_AES_DeEncry_ERROR_PROC;
    }


     // encrypt (iv will change)
    AES_cbc_encrypt(pSrcOB->_pData, pDstOB->_pData, pSrcOB->_size, &aes, iv, AES_DECRYPT);

    _SSL_WRAP_OBFree(pSrcOB);
    return pDstOB;

SSL_WRAP_AES_DeEncry_ERROR_PROC:
	_SSL_WRAP_OBFree(pSrcOB);
	_SSL_WRAP_OBFree(pSrcOB);
	return NULL;

}
