rule Win_Spyware_409_2
{
strings:
	$a0 = { 4932cc32a5fc38e8ec5b12ccf08f7696a65c00ff9a2e3142b6befd9dbd742d758986a18faf1296fa1ad75f9f8d8e62ce6224cd9427f4c776f2fd6d94088cd3f529b730f5526f43941dfa77610623 }

condition:
	$a0
}

        
