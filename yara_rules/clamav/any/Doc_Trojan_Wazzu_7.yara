rule Doc_Trojan_Wazzu_7
{
strings:
	$a0 = { 646e106907526e64576f7264646e106712806a0677617a7a7520646e106710c0646e081a1d64641a1b64641b6907526e64576f7264646e08675600732e01646e082f690364 }

condition:
	$a0
}

        