rule Win_Trojan_Buzus_64
{
strings:
	$a0 = { 68f802000068000000006888865300e89c40000083c40c6800000000e895400000a38c865300680000000068001000006800000000e882400000a388865300684e5d53008f0590865300e8918a0000e8178a0000e8e7810000e86a6f0000e81f670000e8f2650000e832600000e8135a0000e879580000e8e4520000e8a35100 }

condition:
	$a0
}

        