rule Win_Spyware_3920_1
{
strings:
	$a0 = { 60e8000000005d81ed2a27400031c04083f006403d401f00007507be6a274000eb02 }

condition:
	$a0
}

        
