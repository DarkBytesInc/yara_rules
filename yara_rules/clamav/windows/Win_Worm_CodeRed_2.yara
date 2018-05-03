rule Win_Worm_CodeRed_2
{
strings:
	$a0 = { 8bf450ff9590feffff3bf490434b434b898534feffffeb2a8bf48b8d68feffff518b9534feffff52ff9570feffff3bf490434b434b8b8d4cfeffff89848d8cfeffffeb0f8b9568feffff83c201899568feffff8b8568feffff0fbe0885c97402ebe28b9568feffff83c2018995 }

condition:
	$a0
}

        
