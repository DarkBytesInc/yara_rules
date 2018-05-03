rule Win_Worm_Stration_541
{
strings:
	$a0 = { c5c0c5c4dcc58bced9d9c4d9ab0000131d0a161d144b4a561c14147800000050666e7341687554 }

condition:
	$a0
}

        
