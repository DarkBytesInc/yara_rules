rule Win_Spyware_Banker_2124
{
strings:
	$a0 = { da7a7538fd4ae37eaf572386638acc0ae4299afdc01a681f8c3a12687d0e224169e9937ada51e49b78b7f1cda30ed811b753ccb1e2170fc1ebaab23f8fddd7a64a2fed28f1d72e7226e4a545fba521e7b01e47382db1af8a203d5af5e839077d46f81c9aea1b6201fde65df82ec18d9a733bead84d8a637d }

condition:
	$a0
}

        
