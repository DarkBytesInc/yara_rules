rule Win_Trojan_Spyvir_1
{
strings:
	$a0 = { 1b9000001000cc01ca05a004e9026f10c8002800f9047801780124001ebb00014b4b4b2e813f5246751c8cc82d1000 }

condition:
	$a0
}

        
