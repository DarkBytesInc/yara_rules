rule Win_Trojan_Mybot_130
{
strings:
	$a0 = { af1fd9bb6b789cb5766bd0f64ac14417ebf59a17b3added6ac6b6b317d375e5adddd3a12022ca67f9fab8c192ff100f9e4928854ca70dc667c686180078ef9c89b70dbfe15bb8f91aefb3b0b6d12503dd35f288323b5edb6e5ee04da7e0698fd82ddcfd176abe43571cf26b1 }

condition:
	$a0
}

        
