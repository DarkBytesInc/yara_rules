rule Win_Downloader_Small_2531
{
strings:
	$a0 = { e1b689e581ec9400000081ecfc0c000080cdda89e38925f94f4000a1396040008983d9000000a13d60400080e6bb8983 }

condition:
	$a0
}

        
