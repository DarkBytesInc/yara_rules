rule Win_Trojan_Rukap_55
{
strings:
	$a0 = { 7af53a47537aa6dae1e69036c664254307a84c351a137a6b9bad0699340ea1ffddee515d33af553e1e717ae78cfe487d71c10c3e56c1b75f82115703a8a752b9be460b81a16a71a2 }

condition:
	$a0
}

        
