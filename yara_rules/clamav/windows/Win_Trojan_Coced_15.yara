rule Win_Trojan_Coced_15
{
strings:
	$a0 = { ebe820e6e5f0f2e2fb0a200909202573200a20cdeee2fbe520e2e5f0f1e8e820cde0e5e1f9eae020d1eef1e5e4e5e920e2fb20e2f1e5e3e4e020f1eceee6e5f2e520ede0e9f2e820ede0200a20687474703a2f2f6e616562692e7473782e6f7267200a20000076657273696f6e }

condition:
	$a0
}

        