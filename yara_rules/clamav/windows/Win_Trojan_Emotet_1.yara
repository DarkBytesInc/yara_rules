rule Win_Trojan_Emotet_1
{
strings:
	$a0 = { 558bec83ec14565357a1b8a340008b0db8a240003bc1752ba1b8a340008b0d98a340003bc17e1cff0520a34000eb14833da8a34000017402eb4b33c05f5b5e8b }

condition:
	$a0
}

        
