rule Win_Trojan_Ibounce_1
{
strings:
	$a0 = { 4100ba44db4000e87d5effff8b55fce8755effffe85373ffffe8034dffff53e88d7dffff56e8877dffff33c05a5959648910687fd940008d45f4ba03000000e8d559ffffc3e94354ffffebeb5e5b8be55dc3000000ffffffff31000000436f756c64206e6f74206861 }

condition:
	$a0
}

        
