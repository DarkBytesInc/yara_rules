rule Win_Trojan_SdBot_3918
{
strings:
	$a0 = { 63e4d7800f0f482a0b1adc46d9d6e284837e27b8faf5bb3ee2edb1aa49803fd2484a7d44119c78c8728206aad77189f1d4335e9a3a1d8153ea103aaf720025f4a37c05afcab44201baa2eb0e039415e2dff9613620ff03ef9c1dea51 }

condition:
	$a0
}

        
