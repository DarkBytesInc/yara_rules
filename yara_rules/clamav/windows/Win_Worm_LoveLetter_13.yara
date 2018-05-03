rule Win_Worm_LoveLetter_13
{
strings:
	$a0 = { 74726f6a616e2e436f707928746d70202620225c616c5f676f72652e76627322290d0a097370616d2829 }

condition:
	$a0
}

        
