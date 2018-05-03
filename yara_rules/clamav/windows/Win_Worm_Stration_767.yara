rule Win_Worm_Stration_767
{
strings:
	$a0 = { be6450891387f2fae27a229faeb328f87b585135bfd1f8066afcb796cfc04e8948778d461583e6f136588424e6765c725eee3f7dcbcbb2bf461a72f54beae13314c9e6c2aa475c284acd3cfc5d6b376e0ee498196449f598fc }

condition:
	$a0
}

        
