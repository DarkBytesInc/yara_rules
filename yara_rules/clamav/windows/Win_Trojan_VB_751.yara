rule Win_Trojan_VB_751
{
strings:
	$a0 = { 60e8000000008b2c2483c404837c242801750c8b44242489859c0c0000eb0c8b85980c000089859c0c00008db5c40c00008d9d8204000033ff6a4068001000006800200c006a00ff952d0c00008985940c0000e859010000eb20608b859c0c0000ffb594 }

condition:
	$a0
}

        