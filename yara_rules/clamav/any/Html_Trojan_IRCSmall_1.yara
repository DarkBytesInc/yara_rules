rule Html_Trojan_IRCSmall_1
{
strings:
	$a0 = { 6f6e20313a544558543a21646f776e6c6f61642a3a256368616e3a207b206d736720256368616e20646f776e6c6f6164696e6720243220242b202e2e2e207c20646f776e6c6f616420446f776e6c6f616420243220246d697263646972207d }

condition:
	$a0
}

        