rule Win_Trojan_Small_3661
{
strings:
	$a0 = { aa72b1ad674f6afcc24c3c39fe41f40d190ea18e0490fb38e6683a51e581e2838b00ccaad9d871dd5184496564f9f3c17ce2447b9d3be5e93e471fb5ad8309eeed8e333c65ff9d674fef59bfa08497315ad0a1d613f506a5626e }

condition:
	$a0
}

        
