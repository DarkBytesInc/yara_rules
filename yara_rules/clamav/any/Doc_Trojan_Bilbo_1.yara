rule Doc_Trojan_Bilbo_1
{
strings:
	$a0 = { 74697665436865636b6464236901490c6c01002467b780056c010006641d67b88005690149126c0100060c6a0542696c626f1e646e03690d41637469766550726573656e740c }

condition:
	$a0
}

        