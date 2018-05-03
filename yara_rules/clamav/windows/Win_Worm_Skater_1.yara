rule Win_Worm_Skater_1
{
strings:
	$a0 = { 6ff3bb4faa02ffdf9dfd425f60b2f23b15010374696f6e2020437261636b0020ffbf718c3d2fcc31ce640c6493ca29b940ae2d8b0acbfffffff269c146cd7eedbce64f8846b51284d1d851 }

condition:
	$a0
}

        
