rule Win_Trojan_Mybot_5738
{
strings:
	$a0 = { da615380f23fc2ca4114ee98cddfa57618b9ea67d2029da3de7c11e4dc12f674f0150478575f1b23cb1c34bd3feec7d2a9dc601a59972721db39f4d3e2dc558afd9dd08c6cc213f31f93856f87f25159bf1ed9fdfc5b7aa9a4da6fc6e0bf5a16b304b0bc436836af3f6932d9a67613d4c59a307016556ea0f336ec5f410aae51 }

condition:
	$a0
}

        