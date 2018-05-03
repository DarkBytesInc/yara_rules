rule Win_Worm_P2P_4
{
strings:
	$a0 = { 672670688ed526345a346d23decd2ea7122186a60b7a6909fb6c7457d5404ef67909a7c45382f9a8e23a3c4389157677acc032cb7228d7dfab0170fbadccd45b }

condition:
	$a0
}

        
