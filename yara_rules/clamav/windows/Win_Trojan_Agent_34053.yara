rule Win_Trojan_Agent_34053
{
strings:
	$a0 = { b740d189bc455c8af1b0488e8982918cb8ff77b5c37abdf42001498160bac7ff8d3f43e6f8581d075a38986a79ab378a72e4418ebefded672a1664729c52ef78e95cd3daa54b1c7129f04741244c40001c42e23a822b3ca40e06532062adc0b2f63394b0e18118d2f4b17aabc7e4d4b30d78455248b966d23e4563ea3dbd52d9b22ee7b041ea16f0aa0f5f5b }

condition:
	$a0
}

        