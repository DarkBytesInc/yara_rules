rule Win_Spyware_Banker_5102
{
strings:
	$a0 = { bd60170c00a8f7b6bfb2e0c6c3d9c1c9f5e80f5b038d03d682311db1d549324d93d5c5d545432d73c600a6e56634103c3739382e3d520e980d06423028ce394c4a5851bd6a3050c23a3e7a7b5f5c88b33b0c4b4d484f245a4c0cccdc53440c20220ef4f5c58b432201fcea38c424983f6b493b2672c0843225595f2596 }

condition:
	$a0
}

        