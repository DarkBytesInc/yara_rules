rule Win_Spyware_404_2
{
strings:
	$a0 = { 149cc4a35eab7ef9a95e0792d460a2a0fed1302fd6cb5c4cbd3810034d0f9528486053bbec031fb0f652fbed9200ee94020d4da9bf74b49c00a86ef198297d8073b904de1d42088fdc04ad456c02 }

condition:
	$a0
}

        
