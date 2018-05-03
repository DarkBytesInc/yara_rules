rule Win_Ransomware_Locky_32340
{
strings:
	$a0 = { 8d45??5068[4]c745??47657454c745??69636b43c745??6f756e74c645??00ff15[4]50ff15[4]8945??ffd0 }

condition:
	$a0
}

        
