rule Win_Trojan_Small_97
{
strings:
	$a0 = { 54636a2aec6a2b2ac2d22a2a2aa9d2235f28c128c180d51fde186a2ac2ab2c2a2ac3eefeffffe85f0600006a00e8f20500006476394c0c660e660c643c3e4c0c640e0c0c8ce4380a0c0c07cc7800f3397639 }
	$a1 = { b8ff16400080301c403d871740007ef5b84913400080301d403dfe1640007ef5b87b12400080301e403d481340007ef5b8a811400080300c403d761240 }

condition:
	$a0 and $a1
}

        