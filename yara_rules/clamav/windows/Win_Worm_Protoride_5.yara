rule Win_Worm_Protoride_5
{
strings:
	$a0 = { ffffffff0000000000000000000000000100000001000000b8e1410000000000000000000000000000000000123141 }
	$a1 = { 86275616460527f63656373794460000553554253323e246c6c60000250174564744566796365634160737007444943323e246c6c600d70074564755375627e416d65614 }

condition:
	$a0 and $a1
}

        