rule Win_Spyware_Banker_2667
{
strings:
	$a0 = { 9301a6604c9d329b09f6e429c74dd86a7eea75a369b4a12a4c459ee7ffffffff1477b15b9ccaafc99112c5b51a8ab6632cf3d6999096c559dd64d53c27b8a29bffffffa78ac165abbd1b4a8cee1ea9d4a2466263a975f6d3b238837b2b6dffbff8ff }

condition:
	$a0
}

        
