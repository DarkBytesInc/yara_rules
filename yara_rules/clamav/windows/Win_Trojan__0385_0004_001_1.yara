rule Win_Trojan__0385_0004_001_1
{
strings:
	$a0 = { f112b440cd21e8f704b440b90300ba290bcd21e9d700803e820b537503e9d300837c18407203e9 }

condition:
	$a0
}

        
