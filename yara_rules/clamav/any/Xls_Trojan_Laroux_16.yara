rule Xls_Trojan_Laroux_16
{
strings:
	$a0 = { 496620446179284e6f77282929203d20496e7428283331202a20526e6429202b203129205468656e204d7367426f782022596f75277665204265656e20496e666563746564204279204465736c696e6521222c2031362c2022626f6f20686f6f20686f6f2e2e2e2e48612e2e2e205b5642425d22 }

condition:
	$a0
}

        