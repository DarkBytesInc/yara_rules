rule Win_Trojan_Rootkit_75
{
strings:
	$a0 = { 70686964655f6578206973206675636b696e6720796f752073797374656d21 }

condition:
	$a0
}

        
