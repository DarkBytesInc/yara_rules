rule Win_Trojan_W_243
{
strings:
	$a0 = { d3355dd7ecf7e403a0788782ff0f204d8c8d7733322e6d696d6565004d5c3761ff494d452045646974f80101946f9a9f }

condition:
	$a0
}

        
