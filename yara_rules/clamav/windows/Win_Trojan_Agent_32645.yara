rule Win_Trojan_Agent_32645
{
strings:
	$a0 = { b2df45aedfd0a0f6d77d826757b73caedfc8a0eedfd8a0f27f5400d4590767f0ab4a7dd3ddd47d6f1d12f5efd29707bc0c5149b7204666ed473008b5d76580ddfeee7d42b347082f788801abc8ab06f3d47d7c6061 }

condition:
	$a0
}

        
