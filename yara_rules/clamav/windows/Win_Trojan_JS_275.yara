rule Win_Trojan_JS_275
{
strings:
	$a0 = { 746869732e6d683d22[0-16]6c2f392f39626c6f6c6e7065706e396239656e72706739656c72702e6e }

condition:
	$a0
}

        
