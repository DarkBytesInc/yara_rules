rule Win_Worm_Feebs_28
{
strings:
	$a0 = { ce96ef6e0c9447738ee93c69dc6bab13f997a7109ff98bbc50a8570fbba2a70ef95a2c052d2d926d766f4c6387984afb413eadcc58f7e420b0567cdde0be5a7fa6b06a0fe19310a1a3b1c101d57233e9c443a48167f6eb41ac4aa08cc94f56fa }

condition:
	$a0
}

        
