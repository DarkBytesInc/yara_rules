rule Win_Trojan_Constructor_31
{
strings:
	$a0 = { 766972757320696620796f7520636865636b6564204372797074 }
	$a1 = { 537475622e646c6c }
	$a2 = { 6d79706173736573406d61696c2e7275 }

condition:
	$a0 and $a1 and $a2
}

        
