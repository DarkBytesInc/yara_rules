rule Win_Spyware_Zbot_1284
{
strings:
	$a0 = { e8????000068????400059415150e8????0000ffd08bc881e9 }

condition:
	$a0
}

        
