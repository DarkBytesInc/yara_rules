rule Win_Spyware_Banker_3687
{
strings:
	$a0 = { c9a3b907281491c8a815fa430f37bfa3717d0648b14a47335aef4c1c54897d6d9dc51548aeac8dbecffbf1451590fc907676cc4a55d0e96590794c52eb230ceb7b3fc04e339d5c0ed78e5b838ec971ad264ee6e9eaecb0a069eb972030937306756f27460fa07e2725ae56aafc5361bbbec1ce3ab952c22bf3cd64d51cef24250db2e13f896053065dd2570c }

condition:
	$a0
}

        