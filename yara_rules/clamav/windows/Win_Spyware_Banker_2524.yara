rule Win_Spyware_Banker_2524
{
strings:
	$a0 = { 023e55e25aeea832ed98a18fb6f407f706c01b744954ec2cd6a9db0dcb034824c935aa916d8fcc742254c7f7feba8a27ffc1d5a7fe199a68b9e1d7f80c4ce128a0d3ca4c049a70440257c919964cc9949524bac93a1f9d72fd2903443137a1eb4f6f5409b951a303634a00c12fbbe530c08511f86bed0c4911093a56e1dd6c8a1d75cd133bc6f2ab69dae4ec }

condition:
	$a0
}

        