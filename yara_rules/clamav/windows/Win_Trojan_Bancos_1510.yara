rule Win_Trojan_Bancos_1510
{
strings:
	$a0 = { 532b4abf4ae45e9878b29ca49525d368d2cedb8241c5c244a9f37b99553fcdcaef5ea813224ed2ccd17da7606a69b09b44f1b968cddc08bbb27ae06798537047693181fa0cad0d319e87f66dbae97381fae112e507447b783a9d86bca7863e892460e221dce012f4e75414b952a2d50f5e231eb0cb001467fd5689b212135bb651bb60b002728fbe8527fd74fb9427cb8598a7a8ec43 }

condition:
	$a0
}

        