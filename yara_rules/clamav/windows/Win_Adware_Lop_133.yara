rule Win_Adware_Lop_133
{
strings:
	$a0 = { 8a6cdfb201e7afd9f1afb25aa98b8ac8cd52b08c70836fd28e2306c1efac218b4e6e8d64e136b65ce5e9cf2d692d91714d5f82d84306eeb50ba17a4d062d285d6f771d5fcd0a0c6ac8b560d531a842a2b281efb9edafe6429b8a98fd3e8f5db27824 }

condition:
	$a0
}

        
