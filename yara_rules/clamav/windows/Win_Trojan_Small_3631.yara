rule Win_Trojan_Small_3631
{
strings:
	$a0 = { a19ec2e316244952b8a6d3f3e11f0bed6094b02c28af59f927af59f927af59f4e342cdf3eb42d1f398a289dda3588bdd9fa80a6ad8a289de8b725382cade0343a7b389b1f2418a2c28af59f927af59f4db42cdf45f }

condition:
	$a0
}

        
