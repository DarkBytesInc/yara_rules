rule Html_Trojan_FileDownload_packager_exe_1
{
strings:
	$a0 = { 3c61[0-75]687265663d[0-75]7061636b616765722e657865 }

condition:
	$a0
}

        
