rule Win_Trojan_Mybot_7455
{
strings:
	$a0 = { 82d5bee0e6a56ae50ab613772b332ef5a167420b8dc379c2d1e4369d5442efb616cf939a732cec667b35df74872173144bd1586a17effada4f0f933ab5dd5e3e46c6a3e8f7c3d884ca053cf4cb6717fdf4701a528786a5675395c4b42901155adc082da4532897d342535f759a96 }

condition:
	$a0
}

        