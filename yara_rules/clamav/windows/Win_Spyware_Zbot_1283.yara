rule Win_Spyware_Zbot_1283
{
strings:
	$a0 = { 6a??be????4000ff16a3????4000 }

condition:
	$a0
}

        
