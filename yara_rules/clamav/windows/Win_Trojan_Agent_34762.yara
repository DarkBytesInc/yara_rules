rule Win_Trojan_Agent_34762
{
strings:
	$a0 = { a5b4ad1dc0ccdcf8033da7e2000edfe8d5bd6fff1ebb3e259db36ed301235caf6eb0751cfa8e0f9161b975d7d20c134adbd20ebed7bdc41047493dac6903ee4c1bcf56f69158375adca1fc461fdd53b7d71704c09cf4ef70ef2bb3ed24323855 }

condition:
	$a0
}

        
