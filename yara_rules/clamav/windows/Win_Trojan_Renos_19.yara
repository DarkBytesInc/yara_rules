rule Win_Trojan_Renos_19
{
strings:
	$a0 = { feffff018da0fdffff31c1412b8d54ffffff85c972008985c0feffffc9c3cccccccccccc558bec81ec1802000029c081e8001f000081c0cd00000019459083f8007430898d38feffffff851cfeffff4821c831c9ff45c4018d54ffffff31c131c8098d2c }

condition:
	$a0
}

        
