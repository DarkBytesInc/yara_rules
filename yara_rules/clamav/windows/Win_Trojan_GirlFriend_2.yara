rule Win_Trojan_GirlFriend_2
{
strings:
	$a0 = { 6c467269656e642053657276657220312e3335202e20506f7274200000ffffffff010000000d000000ffffffff01000000 }

condition:
	$a0
}

        
