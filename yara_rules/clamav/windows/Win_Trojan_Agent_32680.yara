rule Win_Trojan_Agent_32680
{
strings:
	$a0 = { 83c4048945c88b4dc8894decc745f00000000068b4f200108b55ec52e89221000083c408c745e400000000eb09 }

condition:
	$a0
}

        
