rule Win_Worm_Randon_11
{
strings:
	$a0 = { 73484f6c650d0a3b3b3b3b3b3b3b3b3b3b3b3b3b0d0a0d0a616c696173204e545365727665725363616e207b0d0a202069662028 }

condition:
	$a0
}

        
