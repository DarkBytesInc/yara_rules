rule Win_Trojan_Perl_12
{
strings:
	$a0 = { 6b3d494f3a3a536f636b65743a3a494e45542d3e6e65772850726f746f3d3e277564702729 }
	$a1 = { 6e7428225c6e41554450204261636b646f6f }

condition:
	$a0 and $a1
}

        
