rule Win_Trojan_Delf_1171
{
strings:
	$a0 = { 6805010000686c964e00e80936f3ff8d45f8b968384d008b16e82613f3ff8b45f8e8d214f3ff8bd08d45fce80012f3ff8b4dfcba80384d008bc3e8656c00006aff }

condition:
	$a0
}

        
