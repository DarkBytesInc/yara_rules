rule Win_Downloader_Small_2559
{
strings:
	$a0 = { e580e5e481ec9400000081ecfc0c000089e389256b4e4000a13960400080ee0d8983fd040000a13d60400080e1048983 }

condition:
	$a0
}

        
