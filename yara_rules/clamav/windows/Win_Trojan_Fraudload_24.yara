rule Win_Trojan_Fraudload_24
{
strings:
	$a0 = { 54000000774946616b637979006d5100000000006a34657100007000420068490000004f313230004551770042524f000000000000004663004b000068003970696f000072476800000051007100740046006756000000330000000000005a6b6b56007968004a59433600000000616b }

condition:
	$a0
}

        