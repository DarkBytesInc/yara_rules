rule Win_Spyware_Banker_2093
{
strings:
	$a0 = { d1c410b89d8d5f00eefdcaa6fe3fe5088458916bc1059549e167afefa27a0137093c93412b79972287a6e7b239af4d2ff2c1d63e951147626319f86f38e32df019cd0501a39bbb16b61e057f8b0c }

condition:
	$a0
}

        
