rule Win_Trojan_N_104
{
strings:
	$a0 = { 617374000d001d0055445020426c61737465722076312e353320427920512d626572745d5b0005300c0000ca080000671100009b0a000022012600ff1901004200233e0400006c740000360400000000010002002020100000000000e802000026 }

condition:
	$a0
}

        