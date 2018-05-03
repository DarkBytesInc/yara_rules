rule Win_Worm_Kouds_1
{
strings:
	$a0 = { 726974652022484b43555c536f6674776172655c22202620 }
	$a1 = { 202620225c6d6c222c202231220d }

condition:
	$a0 and $a1
}

        
