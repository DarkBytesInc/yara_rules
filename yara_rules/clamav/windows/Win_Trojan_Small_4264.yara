rule Win_Trojan_Small_4264
{
strings:
	$a0 = { 558bec83c4f0b8401c4800e838000000eb375648008b00e83c69feff8b0d3c574800a13c5648008b008b15e8d24700e83c69feffa13c5648008b00e8b069feff }

condition:
	$a0
}

        
