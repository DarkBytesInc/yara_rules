rule Win_Trojan_Warp_2
{
strings:
	$a0 = { 4157cd213d5052744cb44abbffffcd2183eb0cb44acd21b448bb0b00cd217235488ec026c7060100080050b82135cd21891eaa018c06ac01580e1ffc2d0f008ec0be00018bfeb95700f3a5061f }

condition:
	$a0
}

        
