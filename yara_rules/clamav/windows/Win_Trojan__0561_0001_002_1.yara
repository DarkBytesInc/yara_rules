rule Win_Trojan__0561_0001_002_1
{
strings:
	$a0 = { 0205020089048d96f901b90500b440cd2153558b1481c20301b918058dbea0068db60801e8 }

condition:
	$a0
}

        
