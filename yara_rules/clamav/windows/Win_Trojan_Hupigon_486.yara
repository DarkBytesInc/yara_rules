rule Win_Trojan_Hupigon_486
{
strings:
	$a0 = { 5e38f352da6bd279f4c3da9836439bd63f817ff63a842793830b908233dab5c974ee96d491e932779d16f089fb48e8910a1ebd55958b85cda8428a502cca5a6c4e4d5cc7ec5ec7e9325ac37cbb7131bc809f593a2a06ec7ee1ed8f3ad79ecbd4af3528fe }

condition:
	$a0
}

        
