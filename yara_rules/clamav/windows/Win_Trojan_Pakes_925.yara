rule Win_Trojan_Pakes_925
{
strings:
	$a0 = { 363e0380085a21b6b3e2e5f9f945a6aba3d92323820d488a220622589ceab79fbd9209c564b5b3230082d8c69d02806400468503b78122222621f8bcb0f9dd510000f8eeaa173cec93ee9ce8740980ca1e5d0e44ba269134375c244108497583c4671c586540e0f2d1e441120ab53354e7667f28c0e45075a99ade135960a47b }

condition:
	$a0
}

        