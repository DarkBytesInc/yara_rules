rule Win_Spyware_Banker_1338
{
strings:
	$a0 = { 47f5d1fb67007b27cf71641f179c55032e3b51998dd150d9670b1fd0991cfa80aa82274882f138c98bda79f705bef89bc07e70f418bd56dcc895f7801b1a25e76f41d204 }

condition:
	$a0
}

        
