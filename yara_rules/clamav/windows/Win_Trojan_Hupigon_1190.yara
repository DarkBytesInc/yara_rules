rule Win_Trojan_Hupigon_1190
{
strings:
	$a0 = { a420a1062a2828c8f82b1028402273920708377ab5af7d32ddcef735fc3bf80ef733b902deee40b6f7bc0b76e486b6bc8af560bdabc80ba404bae405ae025d7242fa648af5c905b7380d5c901ae406f5c816bdc82eedc81777320dbb7057bbdcdbbf877ffffff6fbfefefef9f39cfbf7e7df3e7dfbf7ccf3f6fef7fe0cb18201242fda6d367b258ad04487ce }

condition:
	$a0
}

        