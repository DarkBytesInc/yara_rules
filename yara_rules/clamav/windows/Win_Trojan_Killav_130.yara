rule Win_Trojan_Killav_130
{
strings:
	$a0 = { 7365746c6f63616c0d0a736574202f6120[0-10]202d20310d0a63736372697074202f2f6e6f6c6f676f[0-20]2e766273 }

condition:
	$a0
}

        
