rule Win_Trojan_Agent_33109
{
strings:
	$a0 = { f3eccd58c24d6b1e499fb1b4d3548ba6bea89a84acf7cfa724373ed9bfa9b420a4fb334ad83be4402ede34c24405cfdf9e50839fdeb16229ddd8b8e97fe836aa571364ede28b6e891cb7e781b7b50ca7bbe90de3a41652e64a1e1a317d6d2683cab79967f0d70c302c915cd545fa1df62fb62a }

condition:
	$a0
}

        
