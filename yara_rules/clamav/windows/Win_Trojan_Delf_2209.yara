rule Win_Trojan_Delf_2209
{
strings:
	$a0 = { 0054811aa202b0be15621148045e79243c277b7bbbab7736f72f773b99d7e8efd12dfa3b908bbdc816f6ef20edcc81b5af203560b7579016b215ab918deb920dc7390a6b90755c809ae416d724057082f77241dae446db920bb71077b7146e6e676e6fd9dffffff57bf9f9fdfdfdcf9fdf3e73cf9f39f39e7dffbeffa19c3c1192eca25cf76ddfd8b3662ffa }

condition:
	$a0
}

        