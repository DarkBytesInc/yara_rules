rule Win_Trojan_Silly_35
{
strings:
	$a0 = { 722025256220696e20282a2e6261742920646f20736574205e3d2525620d0a66696e6420225e223c255e253e6e756c0d0a6966206572726f726c6576656c20312066696e6420225e223c25303e3e255e250d0a }

condition:
	$a0
}

        