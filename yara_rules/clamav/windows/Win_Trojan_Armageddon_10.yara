rule Win_Trojan_Armageddon_10
{
strings:
	$a0 = { 909090900a202020202020202020202020202020203c203c203a3a2041526d61474564446f4e2054726f }

condition:
	$a0
}

        