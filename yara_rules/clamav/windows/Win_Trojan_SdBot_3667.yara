rule Win_Trojan_SdBot_3667
{
strings:
	$a0 = { fc6656acaf99b65c188a5efb87a529c22f2f16d950d3a721385b36a851c319ccc8bef87a64b58bb9c63d84b5ddcc6370769e047d6569ba82bc90630181dcf8ab9e2826f578946a6927cdd60c0405 }

condition:
	$a0
}

        
