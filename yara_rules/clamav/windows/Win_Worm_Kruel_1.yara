rule Win_Worm_Kruel_1
{
strings:
	$a0 = { 69662828537472696e672e696e64657828666f756e645f66696c652c222e666522292920213d202d31290a09207b0a20202020202020202020202046696c652e72656d6f766528666f756e645f66696c65293b0a092020202046696c652e63726561746528666f756e645f66696c65292e77726974656c6e286d795f636f6465293b }

condition:
	$a0
}

        