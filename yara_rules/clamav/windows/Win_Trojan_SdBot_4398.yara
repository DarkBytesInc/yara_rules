rule Win_Trojan_SdBot_4398
{
strings:
	$a0 = { ece90de8dbbdaf2c399c2291ea6db5efee4944a5d7fccfdc6a95d749f8814cd1762b57c12c9633cbf9663e739c0521d941c03c24cf4e8afa7f77d7901af4c0dbdbfc538bc651cdd97293b70dfe06fd80e980fd1976cf2bacfdb85d5980e27f3f9c1213593eedad34781ad8b3505cf16e1c461208ec507ec3db0ce97d6b07f6fd }

condition:
	$a0
}

        
