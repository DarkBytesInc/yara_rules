rule Win_Trojan_PinkRen_1
{
strings:
	$a0 = { 70696e6b20666c6f7964202d207769736820796f7520776572652068657265 }
	$a1 = { 7868725f73656e642822706f7374222c22687474703a2f2f73686172652e72656e72656e2e636f6d2f73686172652f7375626d69742e646f222c646174612c2270726573656e642229 }

condition:
	$a0 and $a1
}

        