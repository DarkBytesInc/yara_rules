rule Html_Trojan_FileDownload_fputlsat_dll_1
{
strings:
	$a0 = { 3c61[0-75]687265663d[0-75]667075746c7361742e646c6c }

condition:
	$a0
}

        
