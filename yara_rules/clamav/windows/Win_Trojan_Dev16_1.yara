rule Win_Trojan_Dev16_1
{
strings:
	$a0 = { 3136206e65656420696e20776f21203e3e20633a5c6175746f657865632e6261740d0a6563686f206563686f20797c20666f726d617420653a202f71202f75202f763a44653136203e3e20633a5c6175746f657865632e6261740d0a6563686f206563686f20797c20666f726d }

condition:
	$a0
}

        