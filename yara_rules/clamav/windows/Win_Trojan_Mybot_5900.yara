rule Win_Trojan_Mybot_5900
{
strings:
	$a0 = { 2b61a34a127fd6b7b367b8c8a28e08c390c1a9ad71cb52e9885d581f4f3e46a4525a413869643e613c5ecbfd30cfaaeced321255d2c3ac60c0e17a3bc4a7833daf42e6864e752fc388bf43ed6523e5e6483dc4397644012c0fffe7fba51220341548b87d78bc9ac685c07958d1673c }

condition:
	$a0
}

        