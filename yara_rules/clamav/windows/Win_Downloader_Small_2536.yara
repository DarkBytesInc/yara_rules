rule Win_Downloader_Small_2536
{
strings:
	$a0 = { e534b281ec9400000081ecfc0c000080f22a89e32c3d8925214d4000a12c6040008983a1080000a12860400080cde389 }

condition:
	$a0
}

        
