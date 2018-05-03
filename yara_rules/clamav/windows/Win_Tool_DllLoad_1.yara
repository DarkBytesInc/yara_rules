rule Win_Tool_DllLoad_1
{
strings:
	$a0 = { 6b6b6c646c6c2e646c6c003f446c6c4d657373616765426f784040594158504144405a }

condition:
	$a0
}

        
