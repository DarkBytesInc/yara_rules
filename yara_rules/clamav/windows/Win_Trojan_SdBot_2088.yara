rule Win_Trojan_SdBot_2088
{
strings:
	$a0 = { 94c09bf88b202cd26fbec3d2e90b1a8f9c0455ca05227cef5217ab29aaec0304f8d2f9e882a9b1a7da96d472048078b6c5f80be0233073636a672ec23bf275e12b9c5fbb5f60185037b4e7ea35bbe964446e }

condition:
	$a0
}

        
