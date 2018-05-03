rule Win_Tool_Shellcode_13631_1
{
strings:
	$a0 = { eb165b31c05053bb0d25867cffd331c050bb12cb817cffd3e8e5ffffff63616c632e65786500 }

condition:
	$a0
}

        
