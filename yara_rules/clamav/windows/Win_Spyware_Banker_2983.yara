rule Win_Spyware_Banker_2983
{
strings:
	$a0 = { 7a8993d565897de0c8d46d90f1baa5c56edad4466b3bce02d038c5aeeacce2d2fe82b33b64508c5ed67f82e2b54a907420de0ea96198231a92ce3c46e3a9fac3b2384b0c02edf248ab92e7e616230bfb6221c90a58af314a291a459b5cb09c5cfc2fa582 }

condition:
	$a0
}

        
