rule Win_Trojan_SdBot_1303
{
strings:
	$a0 = { 5642a76fa39e0cf3b148d796aa2d144156e045a2991d429cde75b146859f6672d1d9f54c18432096fa67840202724db660492e67fa0efed977228bf7b92872a68dec8547d272c05cf01a5d44a2c0b12ab1216268dee3243dded1922b2c609bfdd72784d4fd0a5fb54fa9e7a8deebb6c6ef27f1ed6a80dbe5f501d1a2f4f733de248d668e6a0cda55af8d019167801945a97e4b4c029b }

condition:
	$a0
}

        