rule Email_Trojan_Trojan_688
{
strings:
	$a0 = { 412070726f6375726120646520756d61206f706f7274756e69646164652064652074726162616c686f207065e76f20616a7564612061206d696e6861206c6973746120646520636f6e7461746f732c206ae13c42523e7175652073616920646f206d65752074726162616c686f206120706f75636f2074656d706f }

condition:
	$a0
}

        