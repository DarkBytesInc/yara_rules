rule Win_Trojan_psyme_1
{
strings:
	$a0 = { 726f6f74646972203d20776f726b646972202b20225c6d616c77617265686f737422 }
	$a1 = { 67737764656d6f62642e6c6e6b }

condition:
	$a0 and $a1
}

        
