rule Win_Worm_Stration_481
{
strings:
	$a0 = { 5f487752bc284125697226290361fe0437945e96501629de69b78ad430b95cd90d9bbfede3bb4ab84f4bc870776a797934a5066a1f5664caa60f6f1aed899a7170bd798cc6055cd957acca2c784ac471e1b0d879c90ca0d3987eb17dac329ff509ba63f1217b65ced76eedfba6dd4243 }

condition:
	$a0
}

        