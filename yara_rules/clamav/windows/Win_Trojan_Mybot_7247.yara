rule Win_Trojan_Mybot_7247
{
strings:
	$a0 = { edb8762ad7c88c32e5742c571e3fbe2b0b560651e472fc89b335bd863be2d5decbc4e4078fb511021b397c3255f900524f37d33d1c217868ff67e5d3bfd375bc7b4c71861a688ae107f1632381c8 }

condition:
	$a0
}

        