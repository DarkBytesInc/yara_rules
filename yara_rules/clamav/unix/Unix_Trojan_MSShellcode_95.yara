rule Unix_Trojan_MSShellcode_95
{
strings:
	$a0 = { 4831f648f7e6ffc66a025fb0290f05525e505fb0320f05b02b0f05575e4897ffceb0210f0575f85248bf2f2f62696e2f736857545fb03b0f05 }

condition:
	$a0
}

        
