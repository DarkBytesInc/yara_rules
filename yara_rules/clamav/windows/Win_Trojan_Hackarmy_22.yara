rule Win_Trojan_Hackarmy_22
{
strings:
	$a0 = { 33327365727665722e65786500626f74736d75746578780023236f6c64006f70656e006e6f770021534f4654574152455c4d6963726f736f66745c57696e646f77735c43757272656e7456657273696f6e5c0057696e736f636b3332647269766572000000b3784000a1 }

condition:
	$a0
}

        