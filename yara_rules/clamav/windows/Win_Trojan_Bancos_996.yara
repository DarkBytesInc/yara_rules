rule Win_Trojan_Bancos_996
{
strings:
	$a0 = { f760dac8518029ee2e6b37ad0dcc0ea5ad3fbc13d2a267bdf823efa1fbf06b7c6173fdbebf8981dd03065a3429ced387ada3a3dd27ba7481bb0fb8cfe49ad23de050f07f371045071633fccb3f90da7d5aaa53ae0a2da347 }

condition:
	$a0
}

        
