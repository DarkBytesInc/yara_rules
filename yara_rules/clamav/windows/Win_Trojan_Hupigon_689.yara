rule Win_Trojan_Hupigon_689
{
strings:
	$a0 = { 6322acf911d46890bbb58448941cd1377577613627dc658567570972586f2f5b6d1153f8817cc8f9249c95fe3199ffd7e6d18bb15fec61043affaabf }

condition:
	$a0
}

        
