rule Win_Trojan_Startpage_461
{
strings:
	$a0 = { 57bed0dd40008bf8ac340aaa84c075f85e5fc30000000000000000000000627e7e7a302525626578796f27796f6b78696224 }

condition:
	$a0
}

        
