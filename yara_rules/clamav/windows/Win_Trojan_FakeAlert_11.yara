rule Win_Trojan_FakeAlert_11
{
strings:
	$a0 = { ff1395d4fdffff099544ffffff89951cfeffff1995d8fdffff2995e8fdffff2b9548feffff31c9138d90feffff83c11131d121d1098d44fdffff898d44ffffff118d50ffffff81c1000d00001b8df0feffff85c97732219598fdffff2995b8fdffffbaa0 }

condition:
	$a0
}

        
