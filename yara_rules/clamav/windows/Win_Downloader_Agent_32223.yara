rule Win_Downloader_Agent_32223
{
strings:
	$a0 = { b24846743a5543e295f11d412ddae5d8e89ca120cbf6008b5b998d8d2fb878e1e2d71929eb60b7645bb6b24cf6a0644fd90d0a57c4ec158550e4656fdbd8830b02aad939f2ebc12886fc20cb7413458180f1131de0c50db4e947132ee0a17a466ec25011ce46325c11432b0887e81471c89d5c0f81d03b3795c2750cc0323aa1f7cd3ba13dbcde32a06faf619507a318a22e9db5 }

condition:
	$a0
}

        