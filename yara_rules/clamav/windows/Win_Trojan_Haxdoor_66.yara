rule Win_Trojan_Haxdoor_66
{
strings:
	$a0 = { 636b20796f752c2052616d6f6e63696e0af6e5ff2325735c496e7465726e657420706c6f720b1b4b16ec5c69093d276219ffed7f7f7a6b2e646c6c }

condition:
	$a0
}

        
