rule Win_Trojan_Inject_104
{
strings:
	$a0 = { 68e0164000e8eeffffff000000000000300000003800000000000000ee0aa177af3c8748869453aec6529080000000000000010000002d433030302d6c736173730030300000000001000b00b82d400000000000ffffffffffffffff000000001c304000b4324200030000008412400000000000000000000000000084124000 }

condition:
	$a0
}

        