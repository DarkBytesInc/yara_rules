rule Doc_Trojan_TheSecond_1
{
strings:
	$a0 = { 496620686176657361766520416e6420696e66656374656420416e6420284c65667428416374697665446f63756d656e742e4e616d652c203829203c3e2022c4eeeaf3ece5edf22229205468656e }

condition:
	$a0
}

        