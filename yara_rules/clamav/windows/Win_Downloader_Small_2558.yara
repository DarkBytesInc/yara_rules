rule Win_Downloader_Small_2558
{
strings:
	$a0 = { e581ec9400000081ecfc0c000080cd5e89e3892591544000a12860400080e13e8983f10c0000a12c60400080c6f58983 }

condition:
	$a0
}

        
