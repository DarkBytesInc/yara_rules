rule Win_Trojan_Agent_35225
{
strings:
	$a0 = { 24e2e8e7db400ecd8a666af70bc5dcd59c1faf0b109eb1a9c7bedf7f494f00064b5389035381fa4266c3f0d4953e10262ac51d9ab0e0cb3d2d75db73be8889f076d5f0e9536ac426d242bddb0de510f26aa4d3877f867fc2e509a47c }

condition:
	$a0
}

        
