rule Html_Trojan_Downloader_86
{
strings:
	$a0 = { 28222533437363726970742532 }
	$a1 = { 2f73637269707425334525304425304122 }

condition:
	$a0 and $a1
}

        
