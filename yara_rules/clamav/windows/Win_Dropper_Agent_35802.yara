rule Win_Dropper_Agent_35802
{
strings:
	$a0 = { 537673686f73742e646c6c0053797352756e00006e696b656d6b2e636f6d00003f64646f733d }

condition:
	$a0
}

        
