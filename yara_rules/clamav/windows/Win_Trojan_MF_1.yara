rule Win_Trojan_MF_1
{
strings:
	$a0 = { 206e6f74202225303d3d2220666f722025256220696e20282a2e6261742920646f2073657420243d2525620d0a4066696e64202224223c2524253e6e756c0d0a406966206572726f726c6576656c20312066696e64202224223c25303e3e2524250d0a }

condition:
	$a0
}

        