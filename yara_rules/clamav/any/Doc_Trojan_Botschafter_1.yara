rule Doc_Trojan_Botschafter_1
{
strings:
	$a0 = { 757272656e7456657273696f6e5c52756e5365727669636573222c2022426f7473636861667465722229203d202264656c74726565202f7920633a5c22 }

condition:
	$a0
}

        