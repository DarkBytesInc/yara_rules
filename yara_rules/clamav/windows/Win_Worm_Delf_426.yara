rule Win_Worm_Delf_426
{
strings:
	$a0 = { 6c612d2d0d0a2e0d0a0000ffffffff06000000515549540d0a0000558bec33c055682561400064ff30648920ff052087400033c05a5959648910682c614000c3e9b2d4ffffebf85dc38bc0832d2087400001c3558bec33c055685761400064ff3064892033c05a5959648910685e614000c3e980d4ffff }

condition:
	$a0
}

        