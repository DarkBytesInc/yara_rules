rule Win_Worm_Stration_645
{
strings:
	$a0 = { 6fce33202e6578650b5c0fcede91968dffffffe7decee35d786c697c6d287b7d6b6b6d7b7b6e7d6464712861667b7cdfffb7b769086d6c267955727a736e717d687573721c }

condition:
	$a0
}

        
