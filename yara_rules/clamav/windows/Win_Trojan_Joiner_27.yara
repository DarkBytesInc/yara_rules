rule Win_Trojan_Joiner_27
{
strings:
	$a0 = { 7bab6e636cb642d8e6a1534c3b5b4c634c254226926bb598b54f64b67e8adb23a45963e9b567b3dce5bb3a04b819bfc81ae0ae7384dc6860cd8efc0b92ec2ef668585bc10b60375c0f0ada0957d15babae655b4f65e4ee99e6bcae79363cad44491042e1e370885af166e71bca5dce8f2ae0415f81bcdfbffdffe2e9e1 }

condition:
	$a0
}

        
