rule Win_Trojan_NF_2
{
strings:
	$a0 = { b6db929e9691bbb81d5fb5cfb8b3b0bdbeb3e5be8a8b909c93908cbacdb8fa5fdad9d8b5dce5b1b9cdb3dedfbbb81d5fb5d6b8b3b0bdbeb3e5b1b9cdb8fa5fdad9d8b5d5e5be8a8b909c93908cbacdb3dedfbbb88bdfacdedfd3b8fa5fdad9cdac14dfd3b3dedfbbe9b5d88badbebcbabbfebbc5c4 }

condition:
	$a0
}

        
