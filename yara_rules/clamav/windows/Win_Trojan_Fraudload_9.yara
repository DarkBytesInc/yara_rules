rule Win_Trojan_Fraudload_9
{
strings:
	$a0 = { b1ffff5577ffa1c0e4ba7655ea3be474bc27848476f2ff3c15c7df75ac962e2d2276feffffe9473322e6f9ffffa363bcf8ffff08a17a681cc6ffff552266feffff114c22a8ffff532ac2f9fffffb6b54b0ffff4b22aaf9ffffff614cb0ffffffe143dc74 }

condition:
	$a0
}

        
