rule Win_Trojan_Pakes_537
{
strings:
	$a0 = { 7670491dca2a13e90ffae732f19e37aaf6d727acd26b637af67f23356b62e9fcedcc293e2d9cf149c16ae831716a51c7fa3fe3d18c16ea3be1287f3300c1e491156024def17ff4aaa2603b0440361ad7af2fef45fbd11cc2b61f2866dd9c670d7e61fc2d401aaa06e1c8172fdcf345a27639478d98e4525e2df8f1eac262f0d99000439b877e5c3088e3983d }

condition:
	$a0
}

        