rule Win_Trojan_Nuclear_70
{
strings:
	$a0 = { d956c8feaa8bc0bef9a0d5cebcd6aaff2cbec7b4c54718d41f6c9096944d15ae11254d54434343577da4e631297ee0c651826b63634786a3d6d58d2b3144485a35e6b3a11ef5b5102b8d197373739745b630c77f36608755a400ab7fce598dfb620e444343170c0361576d8a7ffd727f1068f56eb9b2cae36e969780860d767fb8087f97f10e0ee8240b0b9390af17101fc6f6f07fc7 }

condition:
	$a0
}

        