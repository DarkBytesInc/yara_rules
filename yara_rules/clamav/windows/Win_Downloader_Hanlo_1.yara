rule Win_Downloader_Hanlo_1
{
strings:
	$a0 = { e80501005c0044006f00730044006500760069006300650073005c00610076 }
	$a1 = { 6d703030372e657865007773325f33322e646c6c005c5c2e5c6176[2-8]00474554202f25733f[0-7]6f73313d2573266f73323d257320485454502f312e300d0a557365722d4167656e743a204d53494520362e3020436f6d70617469626c650d0a486f73743a2025730d0a }

condition:
	$a0 and $a1
}

        