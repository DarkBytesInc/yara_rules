rule Win_Trojan_Vgen_125
{
strings:
	$a0 = { 30722e0d0a404543484f204f46460d0a434f50592025302e42415420433a5c512e434f4d3e4e554c0d0a433a5c51 }

condition:
	$a0
}

        
