rule Win_Trojan_Hupigon_1374
{
strings:
	$a0 = { 705df455292f5434cdccd89ecdcd8c8ea1aa0ba46460cd72dc0bedc09c2f6cfa8b07f08534e2dc0db37b4e2ed661ce3998edfea91ec7c606dfb04885764cf741be200e7f21d106e1b04e38209e57e2395e020e50ff96cd1547b79243cc0378844172 }

condition:
	$a0
}

        
