rule Win_Worm_VB_1000
{
strings:
	$a0 = { 5c00530079007300740065006d00330032005c005a006900700020004d006f006e007300740061002e006500780065 }

condition:
	$a0
}

        