rule Win_Trojan_Bancos_962
{
strings:
	$a0 = { 9ee7e55463e49f6458721b504feccc14c8b0ad05e805c3dfb6c7430034cd5b59853a470ace49cf67e16d67f1fdf788b38dc6525c68b4caa55ec1cfa232464831c2c22de5ad83bb51ff2fc5afbee72364a89b4660860ffe0f }

condition:
	$a0
}

        
