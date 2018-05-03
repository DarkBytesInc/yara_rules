rule Html_Trojan_FileDownload_wintab32_dll_1
{
strings:
	$a0 = { 3c61[0-75]687265663d[0-75]77696e74616233322e646c6c }

condition:
	$a0
}

        
