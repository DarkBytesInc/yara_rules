rule Win_Trojan_Bancos_1427
{
strings:
	$a0 = { f111662e94bbcfe99726407ce4153191142c5441bd8d05addbd2c88de169f72e4a17a9c7556504397fb9438f7abb620d2bcf1c8434d7095d701466c1c61a1c62e06fd5d24733fecd9f76e2df1eee60902d6f31cf9dcac57f7fc5f06b9d }

condition:
	$a0
}

        
