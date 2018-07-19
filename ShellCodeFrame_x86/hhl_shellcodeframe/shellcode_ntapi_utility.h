#pragma once

#include <windows.h>
#include <stdio.h>
#include "nativeapi.h"
#include "ShellCode.h"



#ifdef __cplusplus
extern "C"
{
#endif

	int			my_sh_strcmp(const char *dst, const char *src);
	int			my_sh_stricmp(char *dst, char *src);				//比较大小写不敏感 char
	int			my_sh_wcsicmp(wchar_t * dst1,wchar_t * src1);		//比较大小写不敏感 wchar
	ULONG		my_sh_wcslen (wchar_t * wcs);
	int			my_sh_strlen ( char* str );
	char*		my_sh_strstr (char * str1,char * str2);				//搜索大小写敏感
	char*		my_sh_stristr(char* pString,char* pFind);			//搜索大小写不敏感
	char *		my_sh_strupr(char *str);							//转换成大写字符
	char *		my_sh_strlwr(char *s);								//转换成小写字符

	wchar_t*	my_sh_wcscat (wchar_t * dst,wchar_t * src);
	char*		my_sh_strcat (char * dst,const char * src);		

	int			my_sh_memcmp(void* pv1,void* pv2,size_t  cb);
	void*		my_sh_memcpy(void* pvDest,void* pvSrc,size_t cb);
	void*		my_sh_memset(void* pv,int c,size_t cb);
	void		my_sh_zeromem(PVOID Destination,SIZE_T Length);

	BOOLEAN		Is64Os();
#ifdef __cplusplus 
}
#endif



























void ShellCode_Ntapi_Utility_End();




