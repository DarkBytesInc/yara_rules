rule Win_Trojan_Mybot_8538
{
strings:
	$a0 = { ba8308db8fa5f38be744636d83c63066fbc48d5cc4438983f75b287a5df4983a8e1594864776f884a945551c40a3de776a19d66039326caf5ae18d7e9dcc516ea47980c55c530c470cea87093210a8c12b34301256168a2c6aa374d8a93c0fbe7bb10769f077e9f0eef1fc6d5a452c6bc5143a1849bcf4f02bbd090f2f37cff481a808b7aab969622f148874 }

condition:
	$a0
}

        