rule Win_Trojan_Agent_33117
{
strings:
	$a0 = { f95abe86b6d79cc772f41c806571da475de7d1c49cc012f8f9c4b66ed830d3a9767e09caa8b6fb10ec82f0d3cc359715f9969fd98d6533934d2666ea2a98cacd2db460f6ecfe95a980c9d5a4d449994e21cec560330c03021918c412bbb0623187b2b460b6dfcf8d0bdcd924d8087bed664f63 }

condition:
	$a0
}

        