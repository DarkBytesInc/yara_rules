rule Win_Worm_Gaobot_752
{
strings:
	$a0 = { f0aaa1bf071cce7232125f3520886e6f68b475ed50bfbef2943702dae4d4bc9b48cddff9e4406e0f7461b1d9bcd70c89298165d041512fe52e13dc8b65f87266684fdaf8ee864cc8570ee2bf8cf2e06b8d8d70a5e59e623684d734f44e526d297055a88f1370ea5586ff36f5cecdec888552aa717a6114e55c4a2030e85c706099617afc64fcd781348c7b518f3c1b1ab2 }

condition:
	$a0
}

        