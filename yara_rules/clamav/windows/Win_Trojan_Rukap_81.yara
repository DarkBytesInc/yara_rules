rule Win_Trojan_Rukap_81
{
strings:
	$a0 = { b83e7a46c15cfe4944ee2ac5ae2fd0adea480d3b023f7fb52c42e542187d1d429a847b5117cc9d23b3c116c30469b5cf7158af476ae9a35031cf7e506d8326b85e627caaa73b6dbea9c169419069b28d54a786ef0ce6bcfda4736cceab08b83a3501fe1b6195b1 }

condition:
	$a0
}

        
