rule Unix_Tool_13418_1
{
strings:
	$a0 = { 6a30583430505a48663541306635734f505258 }

condition:
	$a0
}

        
