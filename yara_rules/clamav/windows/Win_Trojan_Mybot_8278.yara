rule Win_Trojan_Mybot_8278
{
strings:
	$a0 = { 9f6372bbd0e8024ab30e055e6eddd76c1ae37557a21fd94e39d6ed5d6e6f76e832fe8e15f488fc4b19bd704c2ab029429208914a1c1e9ac35b88a8656b6152c12ebd14982ad967c0e80125ef8cb8afd2ae0e3de0e48b257dad77c0ac142ffccd }

condition:
	$a0
}

        
