rule Win_Trojan_PerfectKeylogger_9
{
strings:
	$a0 = { 692e646c6c000000756e2e657865000076772e657865000077622e646c6c0000686b2e646c6c0000722e6578650000002e657865000000006b772e6461740000696e73742e646174000000006d632e64617400007469746c65732e6461740000617070732e64617400000000706b2e62696e }

condition:
	$a0
}

        