rule Win_Trojan_Dialer_171
{
strings:
	$a0 = { 616b656e20730a7065206908746869dfb9576c13733129e47474703a2f77c56f8a2f09732e74726166246476618c550bda6e634bfc1f09835003c98bdb64030ab501ac37ebf4b7ffef26205c6f7665722e20 }

condition:
	$a0
}

        