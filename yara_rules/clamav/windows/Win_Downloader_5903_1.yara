rule Win_Downloader_5903_1
{
strings:
	$a0 = { 6a006a004975f951535633c055682341400064ff306489208d45ece84cfeffff8d45fcba38414000e81ff0ffff8d45f8b9704140008b55ece82bf1ffff }

condition:
	$a0
}

        
