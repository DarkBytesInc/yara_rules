rule Win_Downloader_Small_2552
{
strings:
	$a0 = { e580e2aa81ec9400000081ecfc0c000089e380c9ac8925164c4000a15560400080caf48983ed080000a1596040008983 }

condition:
	$a0
}

        
