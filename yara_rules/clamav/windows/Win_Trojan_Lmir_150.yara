rule Win_Trojan_Lmir_150
{
strings:
	$a0 = { e82df276991b5f58db078a311be42c6a4af3bee1dc782bcb1222a0b5f1364c36c184fb7f3902a6e0094b551dd00b7460fcbc2dfc1c6873b24a1e2bfc672d54c6626a2e948b29f477a6381576102bc6e843d17aeb2b6a2f101ad14749130e4a222221d39971fb270111f8072b8afa8a0f18adc1fac71508c8 }

condition:
	$a0
}

        