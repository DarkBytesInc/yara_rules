rule Win_Trojan_SdBot_3467
{
strings:
	$a0 = { 014dfa52c96727a00310e53389b1debfca95316d2aa931f0c93550cb5c51d8d409ef7a1d74016e08220475dbce0ee304aa208cc05209b7a08a4627f6d33edafc2d626e34e7eb3e64c017bea9643c2abcf4b2b51d957834720b29c8672f8d10634c33fbd090bdb46298699e5a87cfd7fdba469357e742 }

condition:
	$a0
}

        