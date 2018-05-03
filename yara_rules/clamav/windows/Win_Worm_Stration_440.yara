rule Win_Worm_Stration_440
{
strings:
	$a0 = { 74b5c2d716807dcd725f9620bbe4ae2dd8aefbef6caebfe4001058ff155c411bb3d70b3854b00eaf0b45f844f5ca5edaf62ab832bcf44d38eeb8e51c0bcb0b8a48576668827a43104a8c3041da59addb }

condition:
	$a0
}

        
