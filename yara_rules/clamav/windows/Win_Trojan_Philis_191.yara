rule Win_Trojan_Philis_191
{
strings:
	$a0 = { c123abb0504433aaa6b44819305ef9782eddb70d2e60d9f3de2998b9f8e3edcf8c3ce687af20458097fa0fdc81a19a14fca9714225fd238d7bb289a0199c35f082414926acd4f45956beed0a59846fc4cae5b0772ae33648e13580f6bf18c9e48f791042633bc1ca35edf86a8b01186425a7b310c4be4a62354f426bfdaa501da9148f78030209527ad12d13aaa9796a }

condition:
	$a0
}

        