rule Win_Trojan_Yellow_2
{
strings:
	$a0 = { 5b83fb037426b80077cd213d2009750fbe5106bf00018b0ead01b80177cd218cc80510008ed050b82f0050cbfc062e8c0685002e8c068b002e8c068f00 }

condition:
	$a0
}

        
