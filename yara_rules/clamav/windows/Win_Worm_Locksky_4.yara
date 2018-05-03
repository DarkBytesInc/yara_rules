rule Win_Worm_Locksky_4
{
strings:
	$a0 = { 4e7de65249545c54689f4228d88aff6174215c00576f726b6f20032db0c34700281547a0c25b732565706feb }

condition:
	$a0
}

        
