rule Win_Trojan_Dialer_39
{
strings:
	$a0 = { 415720332e3000303139304b696c6c65720000303139302d4b696c6c657200303139302d4b696c6c657220322e30202d20436f6e74726f6c2d43656e74657200000000544170706c69636174696f6e000000003031393020416c61726d00005745422e444520536d61727453757266657220322e3300005745422e444520536d61 }

condition:
	$a0
}

        