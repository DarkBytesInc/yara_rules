rule Win_Trojan_Bancos_1826
{
strings:
	$a0 = { 2688c78e83a33fdd67040a012adf0770f1de865c24f45d60aea322c68d0f4028d46f725dba7e165a44c7d792fa5d9d9871eb3fcc2961242ce681691d77edd720975df85642da }

condition:
	$a0
}

        
