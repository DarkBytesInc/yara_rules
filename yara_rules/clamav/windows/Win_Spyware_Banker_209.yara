rule Win_Spyware_Banker_209
{
strings:
	$a0 = { 5757572e524553504f4e53452d4f2d4d415449432e434f4d00000000ffffffff0200000042420000ffffffff3200000068747470733a2f2f777777322e62616e636f62726173696c2e636f6d2e62722f616170662f6161692f6c6f67696e2e70626b0000ffffffff060000004745524542410000ffffffff3700000068747470733a2f2f6f66666963652e62616e636f62726173696c2e63 }

condition:
	$a0
}

        