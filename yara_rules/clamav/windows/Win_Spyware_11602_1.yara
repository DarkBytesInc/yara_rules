rule Win_Spyware_11602_1
{
strings:
	$a0 = { 57696e496e6574 }
	$a1 = { 2f6c696e2e617370000000000000000000000000000000000000000000 }

condition:
	$a0 and $a1
}

        
