rule Win_Trojan_Ehks_2
{
strings:
	$a0 = { 6561645f04022f4b3c74c43e266c743bc2fffba54c5926670f202d2d2045766f6c7548853a01ea76200e3d50c0870072a2e16d0f763e5f3c2f87e93c31041c019ddd70a321b4622d18763d2208080422898ac06566361b2d7f02bd51cfd963953d69736f2d388c09eefd3835392d31229307a73f124040018f58963c42bbecaa214f46019f8c16d430 }

condition:
	$a0
}

        