rule Win_Dropper_Microjoin_15
{
strings:
	$a0 = { eb156b4c5bd7f9e07b710cf1b07984b8296d6fd61b8904d485dcb622c46b8c03090842af6d8c6d46c14e6c6a9c5b486ddf26599ad4f49236ce91bb341aebb66aeb2621b5a29076d19a2c545daf7998a0694b20caaba93612a4ced45d4ba1a4b0c1cebe4ba269cabffddb8f1dfb3bdff37c8f73bf73ce3e5fb0dd27705b }

condition:
	$a0
}

        
