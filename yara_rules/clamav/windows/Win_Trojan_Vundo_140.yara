rule Win_Trojan_Vundo_140
{
strings:
	$a0 = { 0f190595fcb07aeb03faab080f1ba185a21ad0669ce80000000068000000008f0424310424c18424d7ffffffb481ec04000000310c24c04c24d3ddc14424c752c18424f5ffffff23330c24897c24b3310c248b8ca400000000e813000000429e177a0ad8f525f6d5032c97a22253c1c5c58704248984a40000000081c40400000087c16a13c74424c577b328 }

condition:
	$a0
}

        