rule Win_Trojan__0655_0002_002_1
{
strings:
	$a0 = { b90000ba0000cd21b440b91d008d960401cd218db62101b97401518b048dbe0e010305508bd4b4 }

condition:
	$a0
}

        
