rule Win_Trojan_Taipan_1
{
strings:
	$a0 = { 9090909090909090909090b400cd21e80000905e83ee03b8cf7bcd213dcf7b75170e1f81c69002bf9002b90a00fcf3a4061f06b8780050cbb4480a }

condition:
	$a0
}

        
