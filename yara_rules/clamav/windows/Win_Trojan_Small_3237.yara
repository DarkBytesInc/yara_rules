rule Win_Trojan_Small_3237
{
strings:
	$a0 = { 9fec3d2895accba48655c77c865031d4ef38622cef406240b33ea4d3cceca728cc30a8280c563eb5a610b692623ca82861012239a2ecc2e87170da2962ecc835e6fc7d28ed01e238a2ecde40732c3eb39f60 }

condition:
	$a0
}

        
