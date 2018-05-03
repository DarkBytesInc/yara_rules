rule Win_Worm_Stration_689
{
strings:
	$a0 = { 7f9086943cf94414e93004de64b6a6209b74a491011a1a6c87e2c421ba5944744acefabc261a9f4c82dab439bf0fa5974cf7e2fa63657a6949fbb0dec961307151cb69313b071d0e5f085ba44c13c1c3 }

condition:
	$a0
}

        
