rule Win_Trojan_Raven_1
{
strings:
	$a0 = { b3614000f7624000a5614000ffffff7f6d736f66662e657865006a6176616d736b632e646c6c0000106040002a644000006040007664400000000000fc60000000000000 }

condition:
	$a0
}

        