rule Win_Trojan_Sharecom_1
{
strings:
	$a0 = { 02000001002e00ee002e00000000000f633a5c6175746f657865632e6261740c633a5c53686172652e636f6d9a00002e005589e5b800019a7c022e0081ec0001bf50001e57bf00000e579ac7052e00bf50001e57b80100509af5052e009a46022e00bf50001e579a8f072e009a46022e00a3027889160478bf50001e57bfd2021e57ff36027831c05050 }

condition:
	$a0
}

        