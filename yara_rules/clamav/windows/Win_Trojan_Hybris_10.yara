rule Win_Trojan_Hybris_10
{
strings:
	$a0 = { ec505e59979c003a8e1dae3f2a2bf4b1ec6ebcc990eb882bcd5e780abf87fc7cb009211d9089b8d29bd8e8dab7be0b9c7ee0ad2c85c016c7caacdc7d720f6a116c4bf7dd0166c2b07b896c17fdec387e894ce7365c31639cfb91aa4717454e4795ecd6faafb37925da953416 }

condition:
	$a0
}

        
