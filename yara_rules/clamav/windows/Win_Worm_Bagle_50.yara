rule Win_Worm_Bagle_50
{
strings:
	$a0 = { b7baa177244a421c5ca3ca58537a64e82a0b987a43f52a23be6c5b6b98dd4e0d0325e3ccdd6ec3696442465c6a8386837338835985847dffbdee37bb6def634e588b45a7f043ddf1b6cfe61c5574 }

condition:
	$a0
}

        
