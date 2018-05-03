rule Win_Tool_Shellcode_13571_1
{
strings:
	$a0 = { b8ffeffffff7d02be0558bec33ff5783ec04c645f863c645f961c645fa6cc645fb638d45f850bbc793bf77ffd3 }

condition:
	$a0
}

        
