rule Win_Trojan_Glew_1
{
strings:
	$a0 = { 565f2eff34469046545d902e8b0e3500d346005090589058ab5790583dab107d08bb100053c39005003d801dc8f8054ba832872387538df2c716073fa8c0fdaff90e6951eea653c3ddb0007e6921e8a803c05509a90437 }

condition:
	$a0
}

        