rule Win_Tool_Shellcode_13518_1
{
strings:
	$a0 = { eb0f588030954081386861636b75f4eb05e8ecfffffff134a5959595ab53d59795566861636bcd }

condition:
	$a0
}

        
