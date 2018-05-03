rule Win_Worm_Stration_591
{
strings:
	$a0 = { 321d1e02ffff7fff1439101f151d14712777554460425f5355434378555140300034191dbffbdffe0c3d1010131f7c1b765b5f4e784c5b5b3e37e3d2c5c1d4c57ffbfffce6c9ccc5e1a0ac89 }

condition:
	$a0
}

        
