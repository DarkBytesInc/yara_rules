rule Win_Worm_SQL_6
{
strings:
	$a0 = { 4e65742d576f726d2e57696e33322e536c616d6d65725554 }

condition:
	$a0
}

        
