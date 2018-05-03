rule Win_Worm_Bagle_194
{
strings:
	$a0 = { 4b45524e454c33322e444c4c }
	$a1 = { 5d81ed??0000008b5d0c019d??010000fc5553558104241c000000ff5500??8b533c8b741a78fc8d741e18ad91ad50ad03??92ad03??508b }

condition:
	$a0 and $a1
}

        
