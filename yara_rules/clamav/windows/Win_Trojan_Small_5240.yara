rule Win_Trojan_Small_5240
{
strings:
	$a0 = { c623733ff50efadac18ebde4f0e960357266dd152b5d48b059b51746089545b4aa80734bc21f6576d59bf1deb7c81318aa5a7595a65745e70e7570f8fdc56cb69296698bea2e4e11d27578e63dfc }

condition:
	$a0
}

        
