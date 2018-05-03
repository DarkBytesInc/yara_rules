rule Win_Worm_Mytob_184
{
strings:
	$a0 = { c92fdff65ff68f37551d957c09b7f9ba58d3375ecc12478b999afddaab5b0d799ee179966fe8d55afac182e5b0318d9e1bee54063f2c9b9aba9b5d26fb1c661f3e4cf8a132b68a7aa36c996792ff7a06e5d5c2eefba773fd4d7be1cfcaf13dc9af48bb24b887ae814344d5ada55f0abf }

condition:
	$a0
}

        
