rule Win_Spyware_Banker_3373
{
strings:
	$a0 = { 6a64889a01c05ab87cd4e2a476faa2b4cf4f444be0a3fc82d992b8b24eb99b4408e369e2a5436df44ebfc626311ed68d2038f51fde5ddcddb93a8b662aaba1a18fed92c3caec81572cce77c0ea41e7651e24e5a820100d5caae0561623f584e448716b7065dd }

condition:
	$a0
}

        
