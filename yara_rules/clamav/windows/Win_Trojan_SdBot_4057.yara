rule Win_Trojan_SdBot_4057
{
strings:
	$a0 = { c22cf2350a6a6a78f7b2466de133bd876b03260770796f0174616034e742d6a5d412a7dc115ad4963bb2b4de9ab53f716ce7b4df96ff110df30e26cd450229cf43c753cd8dbc211437b128b9fede3d252a830fbafcfd }

condition:
	$a0
}

        
