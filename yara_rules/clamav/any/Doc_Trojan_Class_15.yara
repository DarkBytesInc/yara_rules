rule Doc_Trojan_Class_15
{
strings:
	$a0 = { 2e7265706c6163656c696e65206a2c204368722833392920262072202a20722026206f202a206f20262072202a2072202a206f202a206f20262072202a20722026206f202a206f20262072202a20722026206f202a206f }

condition:
	$a0
}

        