rule Win_Spyware_491_2
{
strings:
	$a0 = { 5eadfd6014ee53605eba98aca152285fd4eb522a1dac526049489e9fa10d645cf4d9411c65a2fbc8cb57456d61ad52f77f3cb98cc95df888b2ba2e5b5eada65fd55745d55ead52f76d3cb98cc95df888b2bac65b5eada65fd557 }

condition:
	$a0
}

        
