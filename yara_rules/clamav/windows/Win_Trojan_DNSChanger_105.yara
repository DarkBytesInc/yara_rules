rule Win_Trojan_DNSChanger_105
{
strings:
	$a0 = { 118a0ac10e83c0a8b9dc869dc1f4369bcd9f7633c0003333d68e4673c1e0a03bc0628732948a6c43e3ca36beb9e23549019b76334cc06243018b9e6fd7ca368ac0613669d5ac7633188a0d8bc0a06643018b768318f5379dc1f24248018b35a9bd8a4c43d1ca363236873649c99a763320e991658154fa884c77ba1fe1177c2b17be }

condition:
	$a0
}

        