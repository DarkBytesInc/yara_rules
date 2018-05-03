rule Win_Worm_Yaha_6
{
strings:
	$a0 = { 759f7275734c616ddfc5b6bfe74269745f3183ef24df24bf6966636fdb7572a0b170056b2bb55f21ff3f58da6e8f196865792c3c42523e64696420 }

condition:
	$a0
}

        
