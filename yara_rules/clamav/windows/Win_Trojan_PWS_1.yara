rule Win_Trojan_PWS_1
{
strings:
	$a0 = { 571034c108688980923455313e8bd8b2b01b560c3c3099594fd41b48a109c075508ad87e8468b80f12920d2c3033c93a8a94d0198014f260880a804181f9e03e }

condition:
	$a0
}

        