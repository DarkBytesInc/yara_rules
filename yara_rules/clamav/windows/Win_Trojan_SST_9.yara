rule Win_Trojan_SST_9
{
strings:
	$a0 = { 62732e4f6e546865466c792043726561746564204279204f6e546865466c79 }

condition:
	$a0
}

        
