rule Win_Trojan_Fakecodec_11
{
strings:
	$a0 = { 09c8c9c3909090558bec81ecb80200008b9518ffffff81ea001200000b95acfdffff239570ffffff21ca83c2252195b0fdffff31ca2955b8899544feffff81fa3d0b0000752c038d2cffffff2b8d5cfeffff8b8d84fdffff898dfcfeffff214db881e9e6 }

condition:
	$a0
}

        
