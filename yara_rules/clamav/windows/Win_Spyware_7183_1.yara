rule Win_Spyware_7183_1
{
strings:
	$a0 = { 5159515960685103000058b916e43c34565e81f2c0f3649850520f315a58 }

condition:
	$a0
}

        
