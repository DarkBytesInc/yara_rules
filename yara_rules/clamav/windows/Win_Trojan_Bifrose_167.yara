rule Win_Trojan_Bifrose_167
{
strings:
	$a0 = { 8801b5ee5d8020d60d002ce739dfbb81530375d11cfb90af805401852047fd001c5109f35fe98cc3006e6075f4affa972a001532250ba57cef62287746eb00aaf630277d }

condition:
	$a0
}

        
