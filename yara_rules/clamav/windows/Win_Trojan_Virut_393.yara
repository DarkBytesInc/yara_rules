rule Win_Trojan_Virut_393
{
strings:
	$a0 = { 33dbb304015c24??68????????c3 }

condition:
	$a0
}

        
