rule Win_Trojan_Bifrose_43
{
strings:
	$a0 = { 7432000b001627c21608bc11d529c0095436003ee00b1515122c085ba55a861f0444c7026a58359ce83a351d1778608780eb4007eb41351e9cfc693520071e0b1b45358219e73f351ca4fbd4ae719a53ea464d0b8054090a085305b949e81ccb02e52913090e62482c3c2d08102e5f18089665cee2781811cec7cc0a31b370c708883ceaf10e35d3c711eec6a1b38c08 }

condition:
	$a0
}

        