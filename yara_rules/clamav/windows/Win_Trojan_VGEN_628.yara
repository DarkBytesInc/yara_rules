rule Win_Trojan_VGEN_628
{
strings:
	$a0 = { 4e5354414c4c2e434f4d0000b20400003d13bb3206f2000700000c0e3efcb301640096120300ec0a322000b000 }

condition:
	$a0
}

        
