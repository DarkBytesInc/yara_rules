rule Win_Worm_Stration_395
{
strings:
	$a0 = { 4db55355f5b815c921ecc9aabd08643c8072ab41c89d975c635500d15e0883d16e8dd459733d9e7247afb2a30444458eedc4d71c9644520baae14fca817c1b2749bcf7c595ffaf0b923578b19c35b2e13c2387faac12960c7f03de818c412022057c4775c6ad7ece217e2e987f2aed65 }

condition:
	$a0
}

        