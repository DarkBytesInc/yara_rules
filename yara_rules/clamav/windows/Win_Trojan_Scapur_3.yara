rule Win_Trojan_Scapur_3
{
strings:
	$a0 = { 72697479ed9bedf25363616e77620372436f6e746502fbdf28fe536572766963655d6f6674776172655c4d0eddf6bf7b726f730d5c57696e646f77735c433e722a56b6e6de2e7369355c527546471c73432673ef3b6e2e65783d }

condition:
	$a0
}

        