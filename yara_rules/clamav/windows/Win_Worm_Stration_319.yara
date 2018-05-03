rule Win_Worm_Stration_319
{
strings:
	$a0 = { 5b93744326526ff01f2e32e2a16e45209eba6f208d03ad3ef16dae924ca371e3a3f52b01f01c94d7fcd3c337fb60a0f23ea37a2e53b6b3509afad5625b34ad7516bb8a560a0d4fbe5fbab154d5b3d75f9ce264d5c972bb89d849ad77775ab660 }

condition:
	$a0
}

        
