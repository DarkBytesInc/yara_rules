rule Win_Dropper_Agent_33616
{
strings:
	$a0 = { b04d8df150379310fef461068cfe258063dba42f6ee08728a89acc79f7acf894eff34e242aa8e5ddced736d19f8a8ad721178f085e75a3e6d89a54d68ddb2865d95f94ce97873e1ef980c135987864c20e3c98e9 }

condition:
	$a0
}

        
