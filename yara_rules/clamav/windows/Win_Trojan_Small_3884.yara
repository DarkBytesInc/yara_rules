rule Win_Trojan_Small_3884
{
strings:
	$a0 = { c3022ccf8de3ef153c8e073afc9690fb5b968c77adb85cb64dee17f737ce5721408d1d0749ce070737a35bc8778e92035ca25c07c18f06cd8b9e47b795eb607a8be592335caa928f636b5e423f193d1748ce073cf80333b60e4809b7378e5ce20719f2b60e195cdb5be00a9f37640b9f8df80fb64dde18f737de06cd8b9f47b722ba068ef28f07b737e3 }

condition:
	$a0
}

        