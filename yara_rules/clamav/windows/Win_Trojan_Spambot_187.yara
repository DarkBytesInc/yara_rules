rule Win_Trojan_Spambot_187
{
strings:
	$a0 = { 75e8faa6ac157827646c0b2382aa99d141af9affff07f87dc1b887e847a97b35d2af0f5f5473c3535a2373f2ed8cffffd7ff2680d059a3a7b4e7dcef2bdec394f10321546faf6fbdc75f350dffffe1ff9d5d082c8232ead7874967075fc80cfc132be05f6a93e3806b98ffffffff }

condition:
	$a0
}

        
