rule Win_Trojan_Agent_35840
{
strings:
	$a0 = { 696f6e5c5750414576656e747300004f4f424554696d6572 }
	$a1 = { 416e746977706133 }
	$a2 = { 676f6e5c4e6f746966795c416e7469777061 }

condition:
	$a0 and $a1 and $a2
}

        
