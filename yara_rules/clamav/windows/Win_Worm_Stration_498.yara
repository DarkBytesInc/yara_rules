rule Win_Worm_Stration_498
{
strings:
	$a0 = { 33283534373f342e092e2833343d291b5a0000f9dbcaeadbd3ceeedfcad6ffbe00000067455474454d5066494c456e414d456120000000dee8f9cb }

condition:
	$a0
}

        
