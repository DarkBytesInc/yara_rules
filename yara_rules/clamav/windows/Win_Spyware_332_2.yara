rule Win_Spyware_332_2
{
strings:
	$a0 = { 5ffe5bc8aaaacacbfc61ddc78e44232d34205bfcd31514e30e870c3fe69d134159e65cc19a8fbf3f87607d890f735b696dc58702dcb2a7b0f9deac9a717e94c56d0f809430bdfcf17379ba0105d94aa18ed1f24106f111c5193f005b1ead96a29288fa6125f997f2d0f6a3b12b6ab54cdff1889f3d0bda1111be90e624901b20661fa4b8cbcd7af8d78737a49afc3258319518d3 }

condition:
	$a0
}

        