rule Win_Trojan_Khorp_1
{
strings:
	$a0 = { 722025300d0a666f722025257a20696e20282a2e7a69702920646f20706b7a6970202d6d2025257a2025300d0a666f722025256120696e20282a2e61726a2920646f2061726a2061202d64202525612025300d0a3a4241542e41726869576f726d2062792044756b652f534d46 }

condition:
	$a0
}

        