rule Win_Spyware_Banker_2269
{
strings:
	$a0 = { 2722a1ce0d03c36d552bc8378580009a988ab4e2dc4aa107c59d536c39a099661ba60f4f2a2e7bc08bde70aed7768507a4c156664e707a2483a107d388fd0158b0495fc45cece00081a2c711100aa523008b9021d0b91f563800080c12c0fd47ec2f3b49453a6000628f501dd5fbb8009ef5940ac7de63933a894900add029921588720058094382d6bd36940047a02703daf789b9fc }

condition:
	$a0
}

        