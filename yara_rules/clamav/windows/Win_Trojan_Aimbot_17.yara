rule Win_Trojan_Aimbot_17
{
strings:
	$a0 = { cf8d4e0161312c5f7e76a1f2d876c4caf57b98db1521c279c45bb9a294f445b882640397d250989a6c95b28eedfc0294a8b073d98bb781185749346377f6dd08c115dc69e8c122278215a457a19ef5b81dc48dad2670199965a08ec2e19ee612ce892fe8c4cfaa0840b3d4864bf0a5104f04e3722351053fdcc1f6 }

condition:
	$a0
}

        