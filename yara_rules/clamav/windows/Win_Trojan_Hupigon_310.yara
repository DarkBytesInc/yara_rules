rule Win_Trojan_Hupigon_310
{
strings:
	$a0 = { da38dc2ec69e2edbb4b48cb915ab7d166b24722f649ba4008b6bb74aeab12c727f8b5eefbd7340972810ecaa4e6f270e2dc0e9dbd8348ad5bf541da195288d47f3079c5c89687e8440f2ac6bb6889015f252ac7a42ed4c44d7a7 }

condition:
	$a0
}

        
