rule Win_Trojan_Mybot_4618
{
strings:
	$a0 = { 737f32dc8e6c646938f5b1817266204643204949e82bf513b1446f753048656c6978d60e2e378e496e736c500168f755418f061269f45c1f3838828f48ed64092654542370318a72b6bb6983910e16af49d12f6c274e81c42204735c6fcef0844743 }

condition:
	$a0
}

        