rule Win_Tool_Dos_11
{
strings:
	$a0 = { 02e8dd00b43dba4202cd217303e9ce0093ba6244b90200e81f01ba5a0352b9d7dae8100103d052bad5cfb90300e8 }

condition:
	$a0
}

        
