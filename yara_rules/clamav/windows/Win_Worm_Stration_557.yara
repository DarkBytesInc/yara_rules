rule Win_Worm_Stration_557
{
strings:
	$a0 = { 59507a575f5056413500000000cbe4e7fbedc0e9e6ece4ed880000000072504165475a565046467d50 }

condition:
	$a0
}

        
