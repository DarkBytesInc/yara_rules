rule Win_Trojan_IRC_Script_127
{
strings:
	$a0 = { 69662028246578697374732868696464656e33322e65786529203d3d202466616c736529207b2065786974207d207c2069662028257365727665726e756d203d3d203029207b2073657420257365727665726e756d2031207d207c202f73657276657220246465636f6465 }

condition:
	$a0
}

        