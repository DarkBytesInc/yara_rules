rule Win_Trojan_W16_6
{
strings:
	$a0 = { 433a5c77696e646f77735c6e6f74657061642e6f6c642225d422637261636b2e657865223e22633a5c77696e646f77735c6e6f74657061642e6578652223d422637261636b2e657865223e22633a5c77696e646f77735c637261636b2e65786522012706fe494e464f3ae5 }

condition:
	$a0
}

        