rule Win_Tool_ARP_1
{
strings:
	$a0 = { 2653746f70000000ffffffff18000000496e6a656374696e672041525020706f69736f6e202e2e2e }

condition:
	$a0
}

        
