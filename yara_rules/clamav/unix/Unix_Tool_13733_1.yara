rule Unix_Tool_13733_1
{
strings:
	$a0 = { 31c0506a6c686c6c616c686e2f6b69682f736269682f75737289e3505389e2505253b03b50cd91 }

condition:
	$a0
}

        
