rule Win_Trojan_Banbra_147
{
strings:
	$a0 = { a1678e985eb927790ca2801ea3dac93601fe5142d68e286961ec48a84fc550b8e47c8388a4ca1d2ecfaec9b07e02ed61cb46fd19c4fb9c992842a34ca8c132f1af436514a3532416fdc8ac4421c44055 }

condition:
	$a0
}

        
