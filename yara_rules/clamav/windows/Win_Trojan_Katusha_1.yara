rule Win_Trojan_Katusha_1
{
strings:
	$a0 = { d109d183f900724319955cfeffff019550feffff238d38ffffff2b8da4feffffba4b00000021ca139568feffff218d4cffffff2b8d60feffff198d80ffffff218d70ffffff898d4cffffff199550ffffff219570feffff11951cffffff09951cfeffff29 }

condition:
	$a0
}

        
