rule Win_Trojan_Mybot_119
{
strings:
	$a0 = { 3e24c250ce7ffff614bbd9eed34ca8aad49af3e0a1831c3c67dbef4e622c6f01306ea56b4b4ca1658e30677edb6f18976edfae0de5327b4f6267e1dbb08717be6433f0c0237e51e20ff5a9dae1488e0b6e9b67c8ce065fcd1a4a53aa30076ebd66d7af39aba3114ef57d }

condition:
	$a0
}

        
