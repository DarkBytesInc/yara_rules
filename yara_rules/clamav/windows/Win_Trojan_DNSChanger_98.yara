rule Win_Trojan_DNSChanger_98
{
strings:
	$a0 = { 8be543b3f4a52b409419d4aae5f56bbfb78f234036b5d46c1ed03b9da1e5a047b61a3efff1a52b34d4c93bffe18d17a9a1e57c40371a1eabc3a52be81e337c40f4d53bffe1a57be88be441bf89e93effe11a5e431ef03bafa1e5d4ca1d1a3eb7f1a52be0bfbe197f28267e340d66c79f6ca0d3e9d2137bd7dee524bfb78d97a9a1e5 }

condition:
	$a0
}

        