rule Win_Trojan_Agent_33082
{
strings:
	$a0 = { 6f9d3f12f6179996e7e01ae75f3aa5bf5a67c27dd0768129e5af922dd841fc6baf6e04e78a7becd1e578b14ecfef2a1a2133dce933b42131db0b3144ce91eb26b366090829690e6493e708 }

condition:
	$a0
}

        
