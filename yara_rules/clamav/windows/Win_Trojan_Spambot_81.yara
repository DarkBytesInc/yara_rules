rule Win_Trojan_Spambot_81
{
strings:
	$a0 = { 64ffffffeb5cb00c27d490ade2e43a5e5b4c2166697225f5dc9fbed23dfe54ffffffff03299b2ac6ec3e56c096689ac12deeb04a76c2a5e0dd4ae01e14893f3b365e98ffffffff1b5b623d4e6394d464ebd82b1f45ea3b0eecc054216e26c50f4a236b085c4d77ffffffff0b371f }

condition:
	$a0
}

        
