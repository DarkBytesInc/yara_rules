rule Win_Trojan_Bancos_1790
{
strings:
	$a0 = { 029d9edd469e454b18341012df0dd1a6e86ce42e075c0bde5029bc8578fb541db6b9cb893803e0721a147a381a2f32e0a261393e53c251144cd4c578aa600b11fbb7ac61708f }

condition:
	$a0
}

        
