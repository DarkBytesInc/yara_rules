rule Win_Spyware_54876_1
{
strings:
	$a0 = { 2400008bff908bff90908bff9090908bff9090b86578650033dbc745b033363054c745b47261792e }

condition:
	$a0
}

        
