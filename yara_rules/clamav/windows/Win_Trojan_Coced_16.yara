rule Win_Trojan_Coced_16
{
strings:
	$a0 = { eae020d1eef1e5e4e5e920e2fb20e2f1e5e3e4e020f1eceee6e5f2e520ede0e9f2e820ede0200a687474703a2f2f7862782e7269616c2e6e65742f6e61656269200a20000000cef8e8e1eae020f1eee7e4e0ede8ff20e2fbf5eee4edeee3ee20f4e0e9ebe00acff0eee2e5f0fcf2e5 }

condition:
	$a0
}

        
