rule Win_Tool_Shellcode_13526_1
{
strings:
	$a0 = { 6a3059648b0985c9780c8b490c8b711cad8b4808eb098b49348b497c8b493c }

condition:
	$a0
}

        
