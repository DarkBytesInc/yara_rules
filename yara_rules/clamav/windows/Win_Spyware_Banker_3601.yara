rule Win_Spyware_Banker_3601
{
strings:
	$a0 = { 48abc87c05a699915ee8ee7475d3187f3d0cf21bd2adcbe69c8fa852f9d6069697bbd87afbbcb309429a74e4c259f23f1c0c178c5b4d28c9cbac8ed9a30603e761152b08698741b746a2837b5e35e7f4f66cdcb10b1a19c956726f0c291d45696296afe07c4abbbc3ff7d6d4bd5216af73ae8a0d93621295668997326827a17dc07d825d323600a37e069452 }

condition:
	$a0
}

        