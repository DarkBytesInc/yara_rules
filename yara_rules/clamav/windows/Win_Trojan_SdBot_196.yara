rule Win_Trojan_SdBot_196
{
strings:
	$a0 = { 77555f55c052223d424039d45dfd3ed7246f7994f9661b5555dcb79ac3165dbe3b1f71da54ed2093d4d92a2f0aa597b752350bbad77246b5476981e96ad71cfc388d49436aee6b87752d9e7ce644782539777d6607a60858c7ea19ca1e80905ce40991a71dc75af4127167e9bf68d733444512a8a2eb2aac678777978e2e96cba4b91797e25cd875001cf293569704f7959caab518 }

condition:
	$a0
}

        