rule Win_Trojan_Xpaj_1
{
strings:
	$a0 = { 24f381f097fb88b081fa2e6578650f8438000000b80200000081fa2e646c6c0f8427000000b80300000081fa2e7379730f8416000000b80400000081fa2e7363720f8405000000b8000000005b5a5933f60f84010000001c233424217424b90b }

condition:
	$a0
}

        