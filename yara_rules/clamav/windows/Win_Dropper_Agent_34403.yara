rule Win_Dropper_Agent_34403
{
strings:
	$a0 = { 53656374696f6e00fd9a805c626c6f77666973682e646c6c[0-50]4465637279707400fd8880 }
	$a1 = { 696e7374616c6c2e626174 }

condition:
	$a0 and $a1
}

        
