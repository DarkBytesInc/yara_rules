rule Win_Trojan_Mybot_5695
{
strings:
	$a0 = { 062cfb5da576243224de20ea671e84f9fa5a99ab45fd27de146776ed292bb81f8dc3f20092b59d15f38efbdbc95c229c78d221e6bb74aa97ae3168a0c3078d53fca4e9a4c79f6c9acf33ec7d105aa963e6e64ce8327fc87fc5be075af6fe367d2eb62ab151c8a5cb6db03828a4fcfdad7cc1c5b4ad6f2193bd827fc5faf6a7de }

condition:
	$a0
}

        
