rule Win_Trojan_Godzina_II_1
{
strings:
	$a0 = { 200032bf9d220001f0ff05004d5a00007a00000020000000ffff200f8b0000000000200f1c0000000000000000 }

condition:
	$a0
}

        
