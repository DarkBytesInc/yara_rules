rule Win_Trojan_Fakedos_1
{
strings:
	$a0 = { 7272656e7456657273696f6e5c5275bfb1bff7073b0366646fa75c082e657dd7fd8778135365536875743b6e7a76696c6567 }

condition:
	$a0
}

        
