rule Win_Worm_SCO_1
{
strings:
	$a0 = { 9edf0b46846831509ae7378affff0dfee03995f456bb23da6de158d24fcf52d861ededf0f6ff0b1affff2ffd2c41597492b399285585b8ee2763a2e42971bc0a5baf0660bd1dff165fea80e64f8e9c118904ba870e9825b548deffffffff7713b254f9a14cfaab5f16d08d4d10d69f6b3a }

condition:
	$a0
}

        
