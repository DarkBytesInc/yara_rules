rule Win_Trojan_SdBot_2404
{
strings:
	$a0 = { 379c6c6313b42a0f2dc5b620539ea65551ab637a6a508b746d91dafcdfd7759fa429b27d3fdfefebf7faa3cd39f775eee787ebbeeeebbe1e1628e7379ed79974ba1267c0a7eb09855c566fbece9ef9be2a1fd0e9b2534d8fe6eb4a4b0fe98c3a9d94ef386845508933b4d80385efd991 }

condition:
	$a0
}

        
