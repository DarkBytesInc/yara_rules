rule Win_Worm_Stration_314
{
strings:
	$a0 = { 65daa2e3dac977e72720a32bea99f21b532e4d40068cd88cef9dead87468773cb84a22809e54976b07d4179f53767a73c5680e063ce2fe5bb1c9799f4fe05c2191b8e82bc46a3e983df3ceeba785873c }

condition:
	$a0
}

        
