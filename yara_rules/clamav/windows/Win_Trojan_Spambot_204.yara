rule Win_Trojan_Spambot_204
{
strings:
	$a0 = { 5dd87df30463f2a5d77b4eb422967a83d4a0c3113cad2437e27c3cf7050b91f10ff0ffff5b3894c3a0173227f75ddc32f3ea8fed3ef92616c1c7deffffffd116d4b57491f0fb3ec2813776f6ea34b1911c4f4dd232908caacdffffffff2b153f8c280d9d9426bb50f6aa550e8eb5 }

condition:
	$a0
}

        
