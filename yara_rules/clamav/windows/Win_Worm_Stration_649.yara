rule Win_Worm_Stration_649
{
strings:
	$a0 = { 6b73536d6a606b7304092b3a19fdffecff27202a21391a2b363a0f4e87d8d3d9f0d8cecedcdad8fcbd0ff6ff83379ca3bfb881a9bfbfadaba98dcc137b5948ff3fc8ff78505b7f484e5075783ca09d8c91b28c8b818a9296a09dd9ffff93e58fb9a88bb5b2b8b3abaf94b3b3b799a49ddc17ff0ffbff250d1b1b09 }

condition:
	$a0
}

        
