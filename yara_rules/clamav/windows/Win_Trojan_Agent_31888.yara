rule Win_Trojan_Agent_31888
{
strings:
	$a0 = { ffd768a0134000538b1d2c104000ffd368040100006830244000ffd768901340006830244000ffd3ff7508e840feffff }

condition:
	$a0
}

        
