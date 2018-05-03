rule Win_Worm_Torvil_2
{
strings:
	$a0 = { d83b1beece85ef1f45e4211160c977a35546238675ab5e0f39d07c0a6226f70a26ed9d9a426997467b5e6869bcede3fb231772ce83fe5b5935caa6711d169f90b47693e553e4cb2b5a6f819946ac3aaa }

condition:
	$a0
}

        
