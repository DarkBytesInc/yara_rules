rule Win_Trojan_Packed_69
{
strings:
	$a0 = { e925e4ffff000000????????1e????000000000000000000 }
	$a1 = { 11110202111111111111111111f9f8f8f8f8f8f8f8f8f911111111f814f914020211110202020202020202020202021111110202111111111111111111f9f8f7f7fbf7f7f9f90711111111f814f91402021111020202020202020202020202f711110202f7f8f7f8f7f8f71111f9f8f9f6f6f7fbf7f90711111111f814f91402 }

condition:
	$a0 and $a1
}

        