rule Win_Trojan_C_316
{
strings:
	$a0 = { 46006100720064006100530061007a }
	$a1 = { 466172646153617a2045584520746f20535746 }

condition:
	$a0 and $a1
}

        
