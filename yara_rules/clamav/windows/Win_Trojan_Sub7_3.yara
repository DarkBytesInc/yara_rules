rule Win_Trojan_Sub7_3
{
strings:
	$a0 = { 2ca7e6254da4a4000868934a4a2f4a73f8715152b470425048732f4a193e0d5375625f304280a179922eecc4cd1b321077 }

condition:
	$a0
}

        
