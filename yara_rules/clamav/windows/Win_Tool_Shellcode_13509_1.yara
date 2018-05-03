rule Win_Tool_Shellcode_13509_1
{
strings:
	$a0 = { 6a70585633346464337630394668 }

condition:
	$a0
}

        
