rule Win_Spyware_Banker_3429
{
strings:
	$a0 = { 85d9a34c532aaadfa818c683fcddf7cbf1b6b2feae7d4a4408ad445879ef68f92a9a2ba3e808cedbf59d25b0f9c058a46daf431d97781e53d20db38185a549fd27aa04f228f1077a452c7cfa137d1c7bbb70c1d88f986d7554995c16eff71a }

condition:
	$a0
}

        
