rule Win_Trojan_Bancos_629
{
strings:
	$a0 = { 738fcf2fa6593ac8e79751d42335ea6f25b87115bf009b315127c8b529a78b14a557a2f0bccc71dcbf8da8b0bafbf64cbfa6bb2a3998533a7ae85245c5f6f67ed8d6dcadbb1ad5f5cf36ba66730a55169443c866f3390dbb5f4cfdb61844ab54ed354dd09ba8ef2beab35cc839f6 }

condition:
	$a0
}

        
