rule Win_Downloader_Small_2542
{
strings:
	$a0 = { e580cc0c81ec9400000081ecfc0c000080ed5789e380c2ef8925264f4000a13960400089836d010000a13d6040008983 }

condition:
	$a0
}

        
