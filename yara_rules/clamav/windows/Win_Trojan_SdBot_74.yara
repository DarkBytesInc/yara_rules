rule Win_Trojan_SdBot_74
{
strings:
	$a0 = { 4e0064924ee3392d755f843bdf26c04bed646ee97106b9896c512f0064fc87180e6661642bbfb95a3aa26722307574662e85bcd6b7e44dea13019ce1252e316b62b3e426a14063122fd42f73a87d6316ca05909d00505249564d5347ca9999883a8e5267b4bfb0099790402e2355 }

condition:
	$a0
}

        