rule Win_Downloader_Dadobra_105
{
strings:
	$a0 = { 2cf408c00a86d6dc57531089bc0132f2810472e0fa418780c1ca15f2b02708fb95d62202b07c2d973814546005ffa074790200894123405741489e0220d075410018ac0017fe37dd500203153230312e31342e3232362af96f58311b42494e005877616273022eff8174626767766a6e6f }

condition:
	$a0
}

        