rule Win_Trojan__0121_0006_000_1
{
strings:
	$a0 = { 01b9be07900503018bd0e851005f07b440cd2126c745150000b440ba4902b90500cd21268b4d0d }

condition:
	$a0
}

        
