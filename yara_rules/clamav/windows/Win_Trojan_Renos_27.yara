rule Win_Trojan_Renos_27
{
strings:
	$a0 = { ff83f90076178b9508feffffff8d00ffffff4229ca83f9007505134d9009d1318d7cffffff114dcc898d04feffffbaeb0000000b95e0feffff4a83c22bff8d50ffffff83fa69761f31c9ff858cfeffff81ea000a00003995f0feffff7609298d84feffff }

condition:
	$a0
}

        
