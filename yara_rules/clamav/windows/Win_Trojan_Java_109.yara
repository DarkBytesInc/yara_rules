rule Win_Trojan_Java_109
{
strings:
	$a0 = { 47616c6c6572795f5669657765720700040100126a6176612f6170706c65742f }

condition:
	$a0
}

        
