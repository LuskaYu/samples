/**************************************************************************//**
*
*                  版权所有 (C), 1999-2013, 中太数据通信公司
*
* @file SslWrap.h
* @brief
* @version 初稿
* @author yuch
* @date 2016年04月26日 
* @note history: 
*     @note    date:      2016年04月26日 
*     @note    author:    yuch
*     @note    content:   新生成函数
******************************************************************************/

#ifndef __SSLWRAP_H__
#define __SSLWRAP_H__


#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

/*
 * 包含头文件
 */
#include <openssl/aes.h>
/*
 * 宏定义
 */
typedef struct _ssl_out_buf {
	unsigned int  _size;
	unsigned char *_pData;
}SSL_OUTPUT_BUF;
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

extern
SSL_OUTPUT_BUF *_SSL_WRAP_OBMalloc(unsigned int len);
extern
void _SSL_WRAP_OBCopy(SSL_OUTPUT_BUF *pDst, unsigned char *pSrc, unsigned int len);
extern
void _SSL_WRAP_OBFree(SSL_OUTPUT_BUF *pData);
extern
void _SSL_WRAP_ResultPrint(SSL_OUTPUT_BUF *pData);
extern
SSL_OUTPUT_BUF * SSL_WRAP_AES_Encry(unsigned char *pSrc, unsigned int uiLen);
extern
SSL_OUTPUT_BUF * SSL_WRAP_AES_Dencry(unsigned char *pSrc, unsigned int uiLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif /* __SSLWRAP_H__ */
