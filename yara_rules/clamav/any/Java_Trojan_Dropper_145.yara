rule Java_Trojan_Dropper_145
{
strings:
	$a0 = { 504b0304 }
	$a1 = { 68704362736b6a45742f414f764a6a526c76572e636c617373 }

condition:
	$a0 and $a1
}

        
