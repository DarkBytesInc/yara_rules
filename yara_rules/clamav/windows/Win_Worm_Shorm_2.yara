rule Win_Worm_Shorm_2
{
strings:
	$a0 = { 891068e73c40008d85dcfcffffba03000000e81ef2ffff8d45f0ba02000000e811f2ffffc3e9fbebffffebdb8bc35f5e5b8be55dc20c000000ffffffff080000005c6c6f672e776e6400000000ffffffff080000005c6c6f672e64617400000000833d1857400000740ba11857 }

condition:
	$a0
}

        