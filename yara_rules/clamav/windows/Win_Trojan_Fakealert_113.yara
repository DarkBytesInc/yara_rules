rule Win_Trojan_Fakealert_113
{
strings:
	$a0 = { 9b05f988466ca6f7695673c07efb62c8887d2c56bba0dcb67644dfb5e74d242f1924a3c2b0359df90d1ec6efa4585661f2b8c7ebc1ae3b2449c44d2413bc6bdb0e7f736d660a2d3ad346dbb4b628cd0d6da7b51e64b2086f5e7d993eb672292ca3354f0e }

condition:
	$a0
}

        
