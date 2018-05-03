rule Win_Worm_Ganda_1
{
strings:
	$a0 = { 83ec58b960594000ba2409000053c74424 }
	$a1 = { 77767574737271732e455845 }

condition:
	$a0 and $a1
}

        
