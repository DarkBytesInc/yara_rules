rule Win_Trojan_Agent_33343
{
strings:
	$a0 = { 169664b99f1af6988cac04d733815fa309d420595dc265502fd9a25215f0236d517e3d33217374e70019a00e4bec15c42c796193a2e91abeae4e4ad86a3c560972b3ca929f3839b2eab37c6a4f8c8d81d68803d56361c3901376 }

condition:
	$a0
}

        