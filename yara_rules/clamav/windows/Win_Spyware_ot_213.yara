rule Win_Spyware_ot_213
{
strings:
	$a0 = { b53bf4634b9fbc57b26408eee5e9a0e8adc8e301c7ff7a01b5df020742396ed39808a6e066d932260408a3774eafbf69ebed380dc456f097ea8f5d3a0a5d290f23de03e3b481c6ef1919cad73fa80b34e01121870fecfed312b02ba5ad5766e54f4f931e }

condition:
	$a0
}

        