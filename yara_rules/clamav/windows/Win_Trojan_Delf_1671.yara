rule Win_Trojan_Delf_1671
{
strings:
	$a0 = { 5c70696666696c655c7368656c6c5c6f70656e5c636f6d6d616e645c222c7300ffffffff3f000000[0-98]2f4745445a4143 }

condition:
	$a0
}

        
