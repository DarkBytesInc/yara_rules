rule Win_Worm_Inmota_2
{
strings:
	$a0 = { 558bec6aff68d850400068c832400064a1 }
	$a1 = { 64656661756c742e68746d[0-223]2e706966 }
	$a2 = { 4344204b657920776562 }

condition:
	$a0 and $a1 and $a2
}

        
