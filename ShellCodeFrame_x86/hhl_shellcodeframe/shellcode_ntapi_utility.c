


#include "shellcode.h"
#include "shellcode_ntapi_utility.h"
#include "nativeapi.h"


//注意写shellcode关闭 security cookie

#define  Shellcode_Final_End  ShellCode_Ntapi_Utility_End

#ifdef HHL_DEBUG
extern PShellData lpData;
#else

#endif





int sh_strlen(const char *str)   
{   
	int len = 0;   
	while (*str ++ != '/0')   
		++ len;   
	return len;   
}

int my_sh_strcmp(const char *dst, const char *src)
{
	int ch1, ch2;
	do
	{
		if ( ((ch1 = (unsigned char)(*(dst++))) >= 'A') &&(ch1 <= 'Z') )
			ch1 += 0x20;
		if ( ((ch2 = (unsigned char)(*(src++))) >= 'A') &&(ch2 <= 'Z') )
			ch2 += 0x20;
	} while ( ch1 && (ch1 == ch2) );
	return(ch1 - ch2);
}

char * my_sh_strlwr(char *s)  
{
	char *str;
	char  c1=0x0;
	str = s;  //记录首地址位置,没有必要判断空值!
	while(*str != '\0')
	{
		c1=*str;
		if(*str > 'A' && *str < 'Z'){  //大写字母则进行转换!
			*str += 'a'-'A';
		}
		str++;
	}
	return s;
}

char * my_sh_strupr(char *str)
{
	char *p = str;
	while (*p != 0)
	{
		if(*p >= 'a' && *p <= 'z')
			*p -= 0x20;
		p++;
	}
	return str;
}


char* my_sh_stristr(char* pString, char* pFind)
{
	my_sh_strlwr(pString);
	my_sh_strlwr(pFind);
	return my_sh_strstr(pString,pFind);
}

int	my_sh_strlen ( char* str )
{
	int len=0;
	for	(len = 0; *str; str++ )
	{
		len++;
	}
	return	len;

}	// End of FUNCTION "strlen"

int my_sh_stricmp(char *dst, char *src)//用于不区分大小写比较字符串是否相同
{
	int ch1, ch2;
	do
	{
		if ( ((ch1 = (unsigned char)(*(dst++))) >= 'A') &&(ch1 <= 'Z') )
			ch1 += 0x20;
		if ( ((ch2 = (unsigned char)(*(src++))) >= 'A') &&(ch2 <= 'Z') )
			ch2 += 0x20;
	} while ( ch1 && (ch1 == ch2) );
	return(ch1 - ch2);
}

//char p[8]=""   p[0]的值是0，后面7个都是随机数。
//char p[8]={0}  p[0]~p[7]全都是0

ULONG  my_sh_wcslen (wchar_t * wcs)
{
	const wchar_t *eos = wcs;

	while( *eos++ ) ;

	return( (ULONG)(eos - wcs - 1) );
}




char* my_sh_strstr (char * str1,char * str2)//搜素大小写敏感
{
	char *cp = (char *) str1;
	char *s1, *s2;

	if ( !*str2 )
		return((char *)str1);

	while (*cp)
	{
		s1 = cp;
		s2 = (char *) str2;

		while ( *s1 && *s2 && !(*s1-*s2) )
			s1++, s2++;

		if (!*s2)
			return(cp);

		cp++;
	}

	return(NULL);
}

int my_sh_wcsicmp(wchar_t * dst1,wchar_t * src1)   //wchar用于不区分大小写比较字符串是否相同
{
	int ch1, ch2;
	ULONG len1,len2;
	ULONG i,j;
	PUCHAR p1,p2,z1,z2;
	char dst[256]={0};
	char src[256]={0};
	p1=(PUCHAR)dst1;
	p2=(PUCHAR)src1;

	len1=my_sh_wcslen(dst1);
	len2=my_sh_wcslen(src1);

	for (i=0,j=0;i<len1;i++,j=j+2)
	{
		dst[i]=p1[j];
	}
	for (i=0,j=0;i<len1;i++,j=j+2)
	{
		src[i]=p2[j];
	}
	z1=&dst[0];
	z2=&src[0];
	do
	{
		if ( ((ch1 = (unsigned char)(*(z1++))) >= 'A') &&(ch1 <= 'Z') )
			ch1 += 0x20;
		if ( ((ch2 = (unsigned char)(*(z2++))) >= 'A') &&(ch2 <= 'Z') )
			ch2 += 0x20;
	} while ( ch1 && (ch1 == ch2) );
	return(ch1 - ch2);
}

wchar_t* my_sh_wcscat (wchar_t* dst,wchar_t* src)
{
	wchar_t * cp = dst;
	while( *cp )
		cp++;                   /* find end of dst */
	while( *cp++ = *src++ ) ;       /* Copy src to end of dst */
	return( dst );                  /* return dst */

}

char*	my_sh_strcat (char * dst,const char * src)
{
	char * cp = dst;
	while( *cp )
		cp++;			/* find end of dst */
	while( *cp++ = *src++ ) ;	/* Copy src to end of dst */
	return( dst );			/* return dst */

}




int my_sh_memcmp(void* pv1,void* pv2,size_t  cb)
{
	size_t  i;
	int     d;
	for (i=0, d=0; i < cb && !d; i++)
		d = (*(const BYTE *)pv1) - (*(const BYTE *)pv2);
	return d;
}

void* my_sh_memcpy(void* pvDest,void* pvSrc,size_t cb)
{
	size_t i=0;
	for (i=0; i < cb; i++)
		((BYTE *)pvDest)[i] = ((const BYTE *)pvSrc)[i];
	return pvDest;
}

void* my_sh_memset(void* pv,int c,size_t cb)
{
	size_t i=0;
	for (i=0; i < cb; i++)
		((BYTE *)pv)[i] = (BYTE)c;
	return pv;
}
void my_sh_zeromem(PVOID Destination,SIZE_T Length)
{
	my_sh_memset(Destination,0,Length);
}



BOOLEAN Is64Os()
{
#ifndef HHL_DEBUG
	//进行shellcode的重定位
	DWORD    offset=ReleaseRebaseShellCode();
	PShellData 	lpData= (PShellData)(offset + (DWORD)Shellcode_Final_End);//生成shellcode时候恢复回来
#endif
	SYSTEM_INFO si;
	lpData->xGetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 )
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

void ShellCode_Ntapi_Utility_End()
{
	int i=0;
	i=i+1;
	return;
}