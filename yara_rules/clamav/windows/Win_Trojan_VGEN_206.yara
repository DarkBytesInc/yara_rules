rule Win_Trojan_VGEN_206
{
strings:
	$a0 = { 03040a0000000600390021001c5f76a9f704000017070000070000003130312e434f4d0f0012032415362738396a }

condition:
	$a0
}

        