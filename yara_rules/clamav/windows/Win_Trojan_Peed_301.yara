rule Win_Trojan_Peed_301
{
strings:
	$a0 = { eb4e51b95802000089d781c1b8240000ab50525183c8ff4005d98c400029db8b0853ffd187d981ebd127000083c36559 }

condition:
	$a0
}

        
