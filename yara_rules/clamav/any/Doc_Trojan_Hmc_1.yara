rule Doc_Trojan_Hmc_1
{
strings:
	$a0 = { 4e6f726d436f64652e7265706c6163656c696e657320792c2022 }
	$a1 = { 466f722078203d203120546f20446f63436f64652e636f756e746f666c696e6573 }
	$a2 = { 4e6f726d436f64652e696e736572746c696e6573203236202b20782c20446f63436f64652e6c696e657328782c203129 }

condition:
	$a0 and $a1 and $a2
}

        