rule Win_Trojan_Mybot_7505
{
strings:
	$a0 = { 7c3db5131b612dc4c942d6273ceae4f84b05a914dbd8d8d1dab1fe025d728c52e2b4119be0608a8c8d51882bd0e440befb08bd6b1905fe9bf0cb1fa68ca1d19ef509b3a5b0cedcf15f801783a4139e522e0f0345b2a2d8f5040b3e65d7485068622a3e0b3a95c3400580d45a1a0121ded8bb5b086a729da9c7656794a2bd3331 }

condition:
	$a0
}

        