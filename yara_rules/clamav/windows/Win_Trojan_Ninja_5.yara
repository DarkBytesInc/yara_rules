rule Win_Trojan_Ninja_5
{
strings:
	$a0 = { e800005e2e807cf8007403e88102b89190cd213d90197457e8ae033d7219744fe856049090909090908cc0488e }

condition:
	$a0
}

        
