rule Win_Spyware_Banker_3261
{
strings:
	$a0 = { f622f70014d468a899a26975c49d3a8d05b8b723cd3040cb16f1d4783cd604758750d6c2d857811da5b2230cf07d674db25ee0b10cb4e8c8f5de6cee6dc60e5f7d41c8aadf0c87d1934382cc927f96999ded4503b502da160304ca53000a1695e0e0ca4e0f6e2cc849ce5b3e2e32a6a8bfc433ddfcdfd8712693d4f66c5577258bcb8ce75b838a153c941ff1 }

condition:
	$a0
}

        