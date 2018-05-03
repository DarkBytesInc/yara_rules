rule Html_Trojan_FileDownload_iacenc_dll_1
{
strings:
	$a0 = { 3c61[0-75]687265663d[0-75]696163656e632e646c6c }

condition:
	$a0
}

        
