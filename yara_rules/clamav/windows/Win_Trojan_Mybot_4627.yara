rule Win_Trojan_Mybot_4627
{
strings:
	$a0 = { ba8807f17275e6ddc045ac7d3131332e4fb56054485bdf818021906275860888bc3dda164e49434b765b6b901a8c30023a390f066606469300ee7c7f6d770f794f4e474a4f296c1de223d016c6303106358e484fd596fcd88f4f4d4f44456f56f001f13330327e343333276add32030e16f7d31b811b8c6e }

condition:
	$a0
}

        