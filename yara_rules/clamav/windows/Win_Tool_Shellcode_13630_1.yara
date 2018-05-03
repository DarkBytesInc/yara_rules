rule Win_Tool_Shellcode_13630_1
{
strings:
	$a0 = { eb165b31c05053bb8d15867cffd331c050bbeacd817cffd3e8e5ffffff63616c632e65786500 }

condition:
	$a0
}

        
