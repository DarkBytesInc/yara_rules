rule Win_Trojan_SdBot_2467
{
strings:
	$a0 = { ce42ec5d23002a8b8007d9808bc2cd35210f201fccca432f00ceab2e6f10ac5e287e86e19f9b3e133130b3da66ccbd650aaf6a1c11bf6884fac8e7dc6dbad92659f22a287de8cb35ea0ba136f31d6880e3bf703099ea8b7c6dc463dfcccbf7d97c72b765f8f593d24faedad09149ac737cb455dca3d6bb4fc08fbf3000ae0a06f84c55dadc9beb83658e8d38 }

condition:
	$a0
}

        