rule Win_Trojan_Expiro_18
{
strings:
	$a0 = { 50515253545556575589e583ec5c535657be0d0000008365f80031ff478365c400e981000000c745c4????????e9f101 }

condition:
	$a0
}

        
