rule Win_Trojan_Subroot_2
{
strings:
	$a0 = { 4e61767733322e657865ec99795c8de9fbc7af73b264e9549a315274649d4165cf8ce5b9450ca55009a1a2a718a512659b425188ecb264cd32631b8c69ca }

condition:
	$a0
}

        
