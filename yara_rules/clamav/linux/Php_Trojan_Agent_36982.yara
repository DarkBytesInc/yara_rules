rule Php_Trojan_Agent_36982
{
strings:
	$a0 = { 3c3f70687020247b225c7834375c7834635c78346642414c5c783533227d5b2262705c7836615c78363475635c783738225d3d225c7836365c7837355c78366563223b247b22474c4f42415c7834635c783533227d5b225c7837387a5c783738655c7836665c7836616b715c7836365c7836335c7837356d225d3d225c783638 }

condition:
	$a0
}

        