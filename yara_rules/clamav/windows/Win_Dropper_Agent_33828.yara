rule Win_Dropper_Agent_33828
{
strings:
	$a0 = { 4a21cc60c7388a22f1647abf068acc8feb87d4da45675cc65eb44e43d56cabae9b1d954035ca768fbb6df320bf460a9bdf361440895e3a6e2460823917d6612a734c652b7a4a2fa11fc7b5f1edbd7f24d0cbb9a70ae782b97c26ca692bea5acdc1dcdc976b2d9e3c2ce4b24437b1ca6e }

condition:
	$a0
}

        
