rule Win_Trojan_Winshell_2
{
strings:
	$a0 = { 5e5ce73980995089dcadb7117275b0bcbbd845e1e96d4172766c21dc36ff5c477d8b4838c20fb43f7226d0f6e8b10c09d4a116f138c08d6c4e38f5e3b953b9bc3aa7192396d139cdfc9674137831160139d445109dc988b989d6a117513ba111b509cae8c415fdd09b4211 }

condition:
	$a0
}

        