rule Win_Downloader_Small_2555
{
strings:
	$a0 = { 5589e581ec9400000081ecfc0c000080e5e089e3b45c89256a4f4000a1286040008983c50c0000a12c60400080f50589 }

condition:
	$a0
}

        
