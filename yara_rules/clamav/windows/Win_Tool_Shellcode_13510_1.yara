rule Win_Tool_Shellcode_13510_1
{
strings:
	$a0 = { 8bec33ff57c645fc63c645fd6dc645fe64c645f8018d45fc50b8c793bf77ffd0 }

condition:
	$a0
}

        
