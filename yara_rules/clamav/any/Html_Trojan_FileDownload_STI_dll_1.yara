rule Html_Trojan_FileDownload_STI_dll_1
{
strings:
	$a0 = { 3c61[0-75]687265663d[0-75]5354492e646c6c }

condition:
	$a0
}

        
