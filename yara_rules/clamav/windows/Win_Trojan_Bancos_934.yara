rule Win_Trojan_Bancos_934
{
strings:
	$a0 = { ca08e08a3e48ceab8eb63c99c52d940a0219f14ec60cd2c45fa824a330f49bc923e6fa61bb66b74a8c8a335b380a7f169197b6467b422015a2e2bdce46a05d797f8229e64d9dc8bcfba98b4b552e73b45bfe0ded9161689e }

condition:
	$a0
}

        
