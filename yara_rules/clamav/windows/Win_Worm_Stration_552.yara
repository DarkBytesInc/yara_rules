rule Win_Worm_Stration_552
{
strings:
	$a0 = { 45677652706d616771714a6763720200a18c8899a88585868ae90000f3dedacbfdc9dedebb00000045686c7d5f684c61 }

condition:
	$a0
}

        
