rule Win_Worm_W_404
{
strings:
	$a0 = { 5c57696e646f77735c43757272656e7456657273696f6e5c52756e }
	$a1 = { 796d7367723a73656e64494d3f2b266d3d }

condition:
	$a0 and $a1
}

        
