rule Win_Spyware_8927_1
{
strings:
	$a0 = { 6a006a004975f9b8e01e4000e813faffff33c05568d81f400064ff306489208d55e8b8ec1f4000e884fdffffff75e868402040008d55e4b85c204000e86ffdffff }

condition:
	$a0
}

        
