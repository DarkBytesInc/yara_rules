rule Win_Trojan_Lowzones_1
{
strings:
	$a0 = { 5365637572697479204c6576656c3a20004d696e0a004d656469756d0a00486967680a0025640a0053657474696e67204c6f77205365637572697479204c6576656c2e2e2e20004f4b0a004f70656e696e672055524c2e2e2e2000696578706c6f72652e6578 }

condition:
	$a0
}

        