rule Win_Trojan_Mono_4
{
strings:
	$a0 = { 8bd28bc08bdb8bc98bf68bff8bed908bd28bc08bd2908bc08bdb8bc9908bf68bff8bed90908bd28bc08bdb908bc98bf68bff8bed9090908bd28bc08bdb8bc98bf68bff8bed90908bd28bc08bdb908bc98bf69090908bff8bed9090 }

condition:
	$a0
}

        
