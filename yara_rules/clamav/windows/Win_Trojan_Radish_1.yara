rule Win_Trojan_Radish_1
{
strings:
	$a0 = { 019050eb019053eb019051eb019052eb019056eb019057eb0190bad521eb019033c9eb0190b8023ceb0190cd21eb019093eb0190b440eb0190b9fc20eb01 }

condition:
	$a0
}

        
