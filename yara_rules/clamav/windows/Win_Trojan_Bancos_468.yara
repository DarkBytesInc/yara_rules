rule Win_Trojan_Bancos_468
{
strings:
	$a0 = { 36e725c2bb95001f6968749ab9322375e715227e39cb966e1f54d85a8449d16ed0ac6ce99666f1f07a85e2894695319fa21279b56886f8642e747a9cde26e1af7dfaa6b9000d7627d9220a7184feb6c7b0da2fcdf77e5a4f6c8872dc35607818362e3cb9266110a56d783882a07944f8797a825651cd66fc4ea10d5319456116717f0e616e5f173e90d10a69419b71d612ce9345ed86 }

condition:
	$a0
}

        