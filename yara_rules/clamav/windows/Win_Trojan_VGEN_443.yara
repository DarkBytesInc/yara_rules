rule Win_Trojan_VGEN_443
{
strings:
	$a0 = { 72198b36010181c60301e86700e825011e061fe8a9001f1e0790908b36010181c61101bf0001b90300f3a4b800 }

condition:
	$a0
}

        