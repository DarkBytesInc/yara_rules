rule Win_Trojan_Taskkill_2
{
strings:
	$a0 = { 7461736b6b696c6c202f66202f696d206578706c6f7265722e657865[0-1]7461736b6b696c6c202f66202f696d }

condition:
	$a0
}

        
