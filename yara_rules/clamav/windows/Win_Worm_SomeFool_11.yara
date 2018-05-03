rule Win_Worm_SomeFool_11
{
strings:
	$a0 = { 4e48561d617163a67272d8291ce7b8cb79b1b98a5a35cb056dc962947b1b1fd3c5e7f25cbe2cc97d3ad8a66f762032b1c70462f95d8d456d }

condition:
	$a0
}

        
