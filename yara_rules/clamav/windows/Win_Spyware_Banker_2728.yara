rule Win_Spyware_Banker_2728
{
strings:
	$a0 = { 0e7377f331cd521d346a56f3e5ebed2f647f3449a711a6775c1a150df9fb37bf8492f99d63015c50709899baf8627da1836d4089ba9343842804 }

condition:
	$a0
}

        
