rule Win_Trojan_SlhBack_1
{
strings:
	$a0 = { ba7c790010b894790010e8defdffffa36c960010baa8790010b894790010e8cafdffffa370960010babc790010b894790010e8b6fdffffa374960010bad0790010b894790010e8a2fdffffbae8790010b894790010e893fdffffba047a0010b894790010e884fdffffba207a0010b894790010e875fdffff }

condition:
	$a0
}

        