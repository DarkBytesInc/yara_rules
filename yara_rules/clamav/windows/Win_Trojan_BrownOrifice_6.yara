rule Win_Trojan_BrownOrifice_6
{
strings:
	$a0 = { 560100063c696e69743e01000f424f55524c436f6e6e656374696f6e010014424f55524c436f6e6e656374696f6e2e6a }

condition:
	$a0
}

        
