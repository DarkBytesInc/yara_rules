rule Win_Trojan_Agent_35973
{
strings:
	$a0 = { 6e303d25[0-16]66747570646174652e79692e6f7267[0-9]6e69636b206e7c78707c7838627837 }

condition:
	$a0
}

        
