rule Win_Spyware_Banker_4733
{
strings:
	$a0 = { 1ccc3d90b4e8f129a524f84110cca8fc34da840551871bad6887155860596b65441488e5a8cf6ca7ce2a03315091e89f5fabf76911874df8280005f8f574433c791fa0499c2a27f05981e655a477fa1447e904694f1b5a5777e0811dad70aa7e6ba9aaee91cc6f987f25d385953ed6dadc2e47e67b2ddefe71a3bc8b25522fa6764303982f5b0522 }

condition:
	$a0
}

        