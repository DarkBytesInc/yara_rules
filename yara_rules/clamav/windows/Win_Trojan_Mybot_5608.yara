rule Win_Trojan_Mybot_5608
{
strings:
	$a0 = { cbf0e5472821dda7e5c9c2d6b23c1d745e46d286adcee2880bdc633a1bbe17651eba06b6c54a5f5dde245384153427c6614f5f022e82c042674ee1fef3bdda372aea5c5cc0bf70d3385e728d78521bad2ad0751dec4946502e5d7eaffd66537c19619dc4898676b96e93c50d5550 }

condition:
	$a0
}

        