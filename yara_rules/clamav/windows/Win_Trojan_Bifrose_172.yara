rule Win_Trojan_Bifrose_172
{
strings:
	$a0 = { bc230109005f102ea2eec0e55507e95d8acb60d0dd441c090081c3a4477996845100d4fb02c58b195d42003cfa1881ce09e7737f2f00eda95a68cc785f2502ff811494ca }

condition:
	$a0
}

        
