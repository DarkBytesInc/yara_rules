rule Win_Trojan_Hupigon_997
{
strings:
	$a0 = { 78d1edb1f20a2b1f5d8d78082e14eaf1f8b33a483cc46c74f6ed6f01ab3a105ba95d9cf48b52df93fb27a2be7d87cdbf1f262bfdfd6a8910a7491026fc4aa07a987505208fffe0368b34701c36f70d5ef32e38157d }

condition:
	$a0
}

        
