rule Win_Trojan_Hacdef_52
{
strings:
	$a0 = { b3f67ceb6cbbdfb478895cd4dfa03ce27fdb5266e0bd35036bcc210624ea18ad0325d7cb9fd27dea3f03238da5a3d62bb9fc365f8db705d728b88696b2f0482a6c85e74fd02b217338c9d88eb0a1a9791191bda0cec5aa4b59e6411e4ee5e29a70876036 }

condition:
	$a0
}

        
