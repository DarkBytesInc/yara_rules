rule Html_Trojan_StartpageEasyWWW_1
{
strings:
	$a0 = { 342a4000042a4000b41640007800000081000000890000008a0000000000000000000000000000000000000065617379777777320065617379777777000050726f6a65637431000001000000402f400000000000483b4000ffffffff00000000 }

condition:
	$a0
}

        