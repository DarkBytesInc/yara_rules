rule Win_Trojan_Agent_33717
{
strings:
	$a0 = { 2d578ce95462f3237fc252fcedf5ff326869499cf9c1d8beff33252e6d07baac57d87e5739f1e13f0ed19ccb3925b639a3345c35a7aa5c9e75cb5e0e7f7eddbc406a5f9dd6ac4dbef0053ccd0493ead05bb50d9099ca1868408fd9d7f68b6a }

condition:
	$a0
}

        
