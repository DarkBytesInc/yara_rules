rule Win_Trojan_Perflog_30
{
strings:
	$a0 = { 696d616765686c702e646c6c00e0000047656e75696e65496e74656c0000000056555381ec280100008bf18bac24380100008d4424246804010000506a00ff150810001085c00f84b300000033db8d44242450ff150410001085c00f849e000000807c04245c0f84ba0000004875f285db0f8488000000680070001053ff150010001085c07578833dbc5c001000747d }

condition:
	$a0
}

        