rule Win_Trojan_Agent_33626
{
strings:
	$a0 = { 6ec44ba74ebffe1ee8cc9800a2a62cbbd570fa1811d6a1cfc2b22e2ad1ddc7684f3296ad145a1da82aa2edc7f2a70753937d0878f12f230f2e478119708003b7127098eb998b23c5d5324477e92bb52f657dfe6eaaeec0fcf33fd7c1 }

condition:
	$a0
}

        
