rule Win_Trojan_W_276
{
strings:
	$a0 = { 696e6952335dbe3c00f7bfad050000f7bf968b76788db61c00f7bfad8b800000f7bf050000f7bf5068000006206a006a016800 }

condition:
	$a0
}

        
