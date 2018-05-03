rule Html_Trojan_FileDownload_peerdist_dll_1
{
strings:
	$a0 = { 3c61[0-75]687265663d[0-75]70656572646973742e646c6c }

condition:
	$a0
}

        
